//! Evidence-bound findings from an agent's static review of the monitored codebase.
use crate::{codebase_revision, store::Store};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
mod tracked_paths;

const PREFIX: &str = "code_finding:";
const LATEST_PREFIX: &str = "code_finding_latest:";

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Actionable,
    Review,
    Resolved,
}

/// An agent-reviewed codebase finding. Do not include credentials or source snippets.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    /// Zero-based index in the latest scan's codebase revisions.
    pub codebase: usize,
    /// Revision of the review that inspected this codebase.
    pub review_revision: String,
    /// Codebase-relative path and one-based line.
    pub path: String,
    pub line: usize,
    /// SHA-256 of the inspected line, excluding its line ending.
    pub line_sha256: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub schema_version: u32,
    /// Existing finding ID when reassessing or moving a previously recorded finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    /// ID of the scan the agent reviewed; stale submissions are rejected.
    pub snapshot_id: String,
    /// Revision of the active code review whose source was inspected.
    pub review_revision: String,
    /// Zero-based index in the latest scan's codebase revisions.
    pub codebase: usize,
    /// Codebase-relative path and one-based line; source content is not copied.
    pub path: String,
    pub line: usize,
    /// SHA-256 of the inspected line; null only when the former file was removed.
    pub line_sha256: Option<String>,
    /// Additional source locations that support the analysis; source content is not copied.
    #[serde(default)]
    pub evidence: Vec<SourceLocation>,
    pub category: String,
    pub title: String,
    pub severity: Severity,
    pub disposition: Disposition,
    /// Agent's evidence-bound reasoning; do not include code or credentials.
    pub analysis: String,
    pub impact: String,
    pub recommendation: String,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct Finding {
    pub id: String,
    pub finding: Submission,
    pub line_sha256: String,
    pub evidence_sha256: Vec<String>,
    /// The former primary file was removed and that absence was verified.
    pub source_removed: bool,
    pub codebase_revisions: Vec<codebase_revision::CodebaseRevision>,
    /// Bounded visible-source fingerprints for roots that cannot be bound by Git.
    pub source_fingerprints: Vec<Option<String>>,
    pub recorded_at: String,
    /// False means the source or monitored revision changed since review.
    pub current: bool,
}

pub(super) fn text_valid(value: &str, max: usize) -> bool {
    static CREDENTIAL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+")
            .expect("static credential pattern")
    });
    !value.trim().is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && !value.contains("-----BEGIN ")
        && !CREDENTIAL.is_match(value)
}

fn tracked(root: &str, path: &str) -> bool {
    crate::codebase_revision::git_command(std::path::Path::new(root))
        .arg("--literal-pathspecs")
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn source_absent(root: &str, relative: &str) -> bool {
    use std::{
        io::ErrorKind,
        path::{Component, Path},
    };
    let root = Path::new(root);
    if root.is_symlink() || root.canonicalize().ok().as_deref() != Some(root) {
        return false;
    }
    let components: Vec<_> = Path::new(relative).components().collect();
    if components.is_empty()
        || components.iter().any(|component| match component {
            Component::Normal(name) => {
                crate::discovery::private_name(&name.to_string_lossy())
                    || crate::inventory::excluded_directory(&name.to_string_lossy())
            }
            _ => true,
        })
    {
        return false;
    }
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component.as_os_str());
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return true,
            Err(_) => return false,
        }
    }
    false
}

pub fn record(store: &Store, submission: Submission) -> Result<Finding> {
    if submission.schema_version != 1
        || submission.line == 0
        || !text_valid(&submission.category, 120)
        || !text_valid(&submission.title, 300)
        || !text_valid(&submission.analysis, 2000)
        || !text_valid(&submission.impact, 2000)
        || !text_valid(&submission.recommendation, 2000)
        || submission.path.is_empty()
        || submission.path.len() > 4096
        || submission.path.chars().any(char::is_control)
        || submission.evidence.len() > 16
    {
        bail!(
            "invalid source finding; provide bounded single-line text, a relative path and a positive line number"
        );
    }
    let _lock = store.lock()?;
    store.ensure_codebases_current()?;
    let snapshot = store.latest()?;
    if submission.snapshot_id != snapshot.id {
        bail!(
            "source finding refers to a stale scan; inspect the current codebase before recording it"
        );
    }
    let review = super::code_review::current_one(store, &snapshot, submission.codebase)?
        .context("start a code review before recording a finding")?;
    if !review.current || review.revision != submission.review_revision {
        bail!(
            "code review changed or its source is stale; restart or reload the review before recording a finding"
        );
    }
    let mut reviews = std::collections::HashMap::new();
    reviews.insert(submission.codebase, review);
    let root = snapshot
        .codebase_revisions
        .get(submission.codebase)
        .context("codebase index outside the monitored scope")?;
    let previous = if let Some(id) = &submission.finding_id {
        let previous: Finding = store
            .meta(&format!("{LATEST_PREFIX}{id}"))?
            .map(|value| serde_json::from_str(&value))
            .transpose()?
            .filter(|finding: &Finding| &finding.id == id)
            .context("unknown code finding ID")?;
        let previous_root = previous
            .codebase_revisions
            .get(previous.finding.codebase)
            .context("previous codebase is unavailable")?;
        if previous_root.codebase != root.codebase {
            bail!("a code finding cannot be moved to another codebase");
        }
        Some(previous)
    } else {
        None
    };
    let source_removed = matches!(submission.disposition, Disposition::Resolved)
        && previous
            .as_ref()
            .is_some_and(|previous| previous.finding.path == submission.path)
        && source_absent(&root.codebase, &submission.path);
    let hash = if source_removed {
        String::new()
    } else {
        let hash = super::citations::line_hash(&root.codebase, &submission.path, submission.line)?;
        if submission.line_sha256.as_deref() != Some(hash.as_str()) {
            bail!("finding source line changed or does not match the inspected line hash");
        }
        hash
    };
    let mut needs_fingerprint = vec![false; snapshot.codebase_revisions.len()];
    let mut fingerprint_eligible = vec![true; snapshot.codebase_revisions.len()];
    needs_fingerprint[submission.codebase] = root.state != codebase_revision::RepositoryState::Git
        || (!source_removed && !tracked(&root.codebase, &submission.path));
    if needs_fingerprint[submission.codebase] && !source_removed {
        fingerprint_eligible[submission.codebase] =
            crate::runners::codebase::source_visible(&root.codebase, &submission.path);
    }
    let mut evidence_sha256 = Vec::with_capacity(submission.evidence.len());
    let mut locations = std::collections::HashSet::new();
    locations.insert((
        submission.codebase,
        submission.path.as_str(),
        submission.line,
    ));
    for citation in &submission.evidence {
        if citation.line == 0
            || citation.path.is_empty()
            || citation.path.len() > 4096
            || citation.path.chars().any(char::is_control)
            || !locations.insert((citation.codebase, citation.path.as_str(), citation.line))
        {
            bail!("invalid or duplicate source evidence location");
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = reviews.entry(citation.codebase) {
            let review = super::code_review::current_one(store, &snapshot, citation.codebase)?
                .context("start a code review for each cited codebase")?;
            entry.insert(review);
        }
        let review = &reviews[&citation.codebase];
        if !review.current || review.revision != citation.review_revision {
            bail!("supporting codebase review changed or its source is stale");
        }
        let cited_root = snapshot
            .codebase_revisions
            .get(citation.codebase)
            .context("evidence codebase index outside the monitored scope")?;
        let hash =
            super::citations::line_hash(&cited_root.codebase, &citation.path, citation.line)?;
        if citation.line_sha256 != hash {
            bail!("supporting source line changed or does not match the inspected line hash");
        }
        evidence_sha256.push(hash);
        needs_fingerprint[citation.codebase] |= cited_root.state
            != codebase_revision::RepositoryState::Git
            || !tracked(&cited_root.codebase, &citation.path);
        if needs_fingerprint[citation.codebase] {
            fingerprint_eligible[citation.codebase] &=
                crate::runners::codebase::source_visible(&cited_root.codebase, &citation.path);
        }
    }
    let source_fingerprints: Vec<Option<String>> = snapshot
        .codebase_revisions
        .iter()
        .enumerate()
        .zip(&needs_fingerprint)
        .zip(&fingerprint_eligible)
        .map(|(((index, _root), needed), eligible)| {
            if !needed || !eligible {
                return None;
            }
            reviews.get(&index)?.source_fingerprint.clone()
        })
        .collect();
    let bound = needs_fingerprint
        .iter()
        .zip(&source_fingerprints)
        .all(|(needed, fingerprint)| !needed || fingerprint.is_some());
    for (index, review) in &reviews {
        let latest = super::code_review::current_one(store, &snapshot, *index)?
            .context("code review is unavailable")?;
        if !latest.current || latest.revision != review.revision {
            bail!("code review source changed while recording the finding");
        }
    }
    store.ensure_codebases_current()?;
    let identity = serde_json::to_vec(&(
        &root.codebase,
        &submission.path,
        submission.line,
        &submission.category,
    ))?;
    let id = if let Some(previous) = previous {
        previous.id
    } else {
        format!("CODE-{}", &crate::digest(&identity)[..20])
    };
    let finding = Finding {
        id,
        finding: submission,
        line_sha256: hash,
        evidence_sha256,
        source_removed,
        codebase_revisions: snapshot.codebase_revisions,
        source_fingerprints,
        recorded_at: crate::now(),
        current: bound,
    };
    let key = format!(
        "{PREFIX}{}:{}:{}",
        finding.id,
        finding.recorded_at,
        uuid::Uuid::new_v4()
    );
    let value = serde_json::to_string(&finding)?;
    let transaction = store.connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )?;
    transaction.execute("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", rusqlite::params![format!("{LATEST_PREFIX}{}", finding.id), value])?;
    transaction.commit()?;
    Ok(finding)
}

pub fn current(store: &Store, snapshot: &crate::model::Snapshot) -> Result<Vec<Finding>> {
    current_filtered(store, snapshot, None)
}

pub(crate) fn current_for_codebase(
    store: &Store,
    snapshot: &crate::model::Snapshot,
    codebase: usize,
) -> Result<Vec<Finding>> {
    current_filtered(store, snapshot, Some(codebase))
}

fn current_filtered(
    store: &Store,
    snapshot: &crate::model::Snapshot,
    codebase: Option<usize>,
) -> Result<Vec<Finding>> {
    let mut statement = store.connection.prepare(
        "SELECT value FROM meta WHERE key GLOB 'code_finding_latest:*' ORDER BY key LIMIT 10001",
    )?;
    let mut rows = statement.query([])?;
    let mut findings = Vec::new();
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > 10_000 {
            bail!("current code findings exceed 10000 entries");
        }
        let finding: Finding = serde_json::from_str(&row.get::<_, String>(0)?)?;
        findings.push(finding);
    }
    if let Some(index) = codebase {
        findings.retain(|finding| finding.finding.codebase == index);
    }
    let comparisons = if findings.is_empty() {
        Vec::new()
    } else {
        codebase_revision::compare(&snapshot.codebase_revisions)
    };
    let actual_fingerprints: Vec<Option<String>> = snapshot
        .codebase_revisions
        .iter()
        .enumerate()
        .map(|(index, root)| {
            if findings.iter().any(|finding| {
                finding
                    .source_fingerprints
                    .get(index)
                    .is_some_and(Option::is_some)
            }) {
                crate::runners::codebase::source_fingerprint(&root.codebase).ok()
            } else {
                None
            }
        })
        .collect();
    let tracked = tracked_paths::collect(snapshot, &findings);
    for finding in &mut findings {
        let root = snapshot.codebase_revisions.get(finding.finding.codebase);
        let fingerprint_matches = |index: usize| {
            finding
                .source_fingerprints
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(|expected| {
                    actual_fingerprints.get(index).and_then(Option::as_ref) == Some(expected)
                })
        };
        let bound = |index: usize, root: &codebase_revision::CodebaseRevision, path: &str| {
            (root.state == codebase_revision::RepositoryState::Git
                && tracked
                    .get(&index)
                    .is_some_and(|paths| paths.contains(path)))
                || fingerprint_matches(index)
        };
        finding.current = codebase_revision::same_revisions(
            &finding.codebase_revisions,
            &snapshot.codebase_revisions,
        ) && comparisons
            .get(finding.finding.codebase)
            .is_some_and(|comparison| comparison.matches)
            && root.is_some_and(|root| {
                if finding.source_removed {
                    (root.state == codebase_revision::RepositoryState::Git
                        || fingerprint_matches(finding.finding.codebase))
                        && source_absent(&root.codebase, &finding.finding.path)
                } else {
                    bound(finding.finding.codebase, root, &finding.finding.path)
                        && super::citations::line_hash(
                            &root.codebase,
                            &finding.finding.path,
                            finding.finding.line,
                        )
                        .is_ok_and(|hash| hash == finding.line_sha256)
                }
            })
            && finding.finding.evidence.len() == finding.evidence_sha256.len()
            && finding
                .finding
                .evidence
                .iter()
                .zip(&finding.evidence_sha256)
                .all(|(citation, expected)| {
                    snapshot
                        .codebase_revisions
                        .get(citation.codebase)
                        .is_some_and(|root| {
                            bound(citation.codebase, root, &citation.path)
                                && comparisons
                                    .get(citation.codebase)
                                    .is_some_and(|comparison| comparison.matches)
                                && super::citations::line_hash(
                                    &root.codebase,
                                    &citation.path,
                                    citation.line,
                                )
                                .is_ok_and(|hash| hash == *expected)
                        })
                });
    }
    if findings.iter().any(|finding| finding.current) {
        let mut relevant = std::collections::HashSet::new();
        for finding in findings.iter().filter(|finding| finding.current) {
            relevant.insert(finding.finding.codebase);
            relevant.extend(
                finding
                    .finding
                    .evidence
                    .iter()
                    .map(|citation| citation.codebase),
            );
        }
        let stable: Vec<bool> = snapshot
            .codebase_revisions
            .iter()
            .enumerate()
            .map(|(index, root)| {
                if !relevant.contains(&index) {
                    return false;
                }
                let revision_matches = codebase_revision::compare(std::slice::from_ref(root))
                    .first()
                    .is_some_and(|comparison| comparison.matches);
                let fingerprint_matches = actual_fingerprints
                    .get(index)
                    .and_then(Option::as_ref)
                    .is_none_or(|expected| {
                        crate::runners::codebase::source_fingerprint(&root.codebase)
                            .is_ok_and(|actual| &actual == expected)
                    });
                revision_matches && fingerprint_matches
            })
            .collect();
        for finding in findings.iter_mut().filter(|finding| finding.current) {
            finding.current = stable
                .get(finding.finding.codebase)
                .copied()
                .unwrap_or(false)
                && finding
                    .finding
                    .evidence
                    .iter()
                    .all(|citation| stable.get(citation.codebase).copied().unwrap_or(false));
        }
    }
    findings.sort_by_key(|entry| {
        let disposition = match entry.finding.disposition {
            Disposition::Actionable => 0,
            Disposition::Review => 1,
            Disposition::Resolved => 2,
        };
        let severity = match entry.finding.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        };
        (disposition, severity, entry.id.clone())
    });
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;

    fn start_review(store: &Store, snapshot: &Snapshot) -> String {
        start_review_for(store, snapshot, 0)
    }

    fn start_review_for(store: &Store, snapshot: &Snapshot, codebase: usize) -> String {
        let previous_revision = super::super::code_review::current_one(store, snapshot, codebase)
            .unwrap()
            .map(|review| review.revision);
        super::super::code_review::record(
            store,
            super::super::code_review::Submission {
                schema_version: 1,
                snapshot_id: snapshot.id.clone(),
                codebase,
                previous_revision,
                status: super::super::code_review::Status::InProgress,
                scope: Vec::new(),
                gaps: Vec::new(),
                uncertainties: Vec::new(),
            },
        )
        .unwrap()
        .revision
    }

    #[test]
    fn cross_codebase_evidence_requires_the_inspected_revision() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join("app.rs"), "fn app() {}\n").unwrap();
        std::fs::write(second.path().join("guard.rs"), "fn guard() {}\n").unwrap();
        std::fs::write(second.path().join("context.rs"), "fn context() {}\n").unwrap();
        let project = uuid::Uuid::new_v4().to_string();
        let mut store = Store::open(&project).unwrap();
        let snapshot = Snapshot {
            schema_version: 1,
            id: "cross".into(),
            project_id: project.clone(),
            profile_sha256: "profile".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            codebase_revisions: vec![
                codebase_revision::capture_path(first.path()),
                codebase_revision::capture_path(second.path()),
            ],
            instances: Vec::new(),
            coverage: Vec::new(),
            cases: Vec::new(),
            partial: false,
            alert_status: "local".into(),
        };
        store.save_snapshot(&snapshot).unwrap();
        let first_revision = start_review_for(&store, &snapshot, 0);
        let second_revision = start_review_for(&store, &snapshot, 1);
        let submission = Submission {
            schema_version: 1,
            finding_id: None,
            snapshot_id: snapshot.id.clone(),
            review_revision: first_revision,
            codebase: 0,
            path: "app.rs".into(),
            line: 1,
            line_sha256: Some(crate::digest(b"fn app() {}")),
            evidence: vec![SourceLocation {
                codebase: 1,
                review_revision: second_revision,
                path: "guard.rs".into(),
                line: 1,
                line_sha256: crate::digest(b"fn guard() {}"),
            }],
            category: "authorization".into(),
            title: "Guard requires review".into(),
            severity: Severity::High,
            disposition: Disposition::Review,
            analysis: "The guard requires review.".into(),
            impact: "Access may be unauthorized.".into(),
            recommendation: "Review the guard.".into(),
        };
        std::fs::write(second.path().join("context.rs"), "fn changed() {}\n").unwrap();
        assert!(record(&store, submission.clone()).is_err());
        std::fs::write(second.path().join("context.rs"), "fn context() {}\n").unwrap();
        assert!(record(&store, submission).unwrap().current);
        let mut next = snapshot.clone();
        next.id = "next-scan".into();
        store.save_snapshot(&next).unwrap();
        let previous = super::super::code_review::current_one(&store, &next, 0)
            .unwrap()
            .unwrap();
        assert!(previous.current);
        let resumed = super::super::code_review::record(
            &store,
            super::super::code_review::Submission {
                schema_version: 1,
                snapshot_id: next.id.clone(),
                codebase: 0,
                previous_revision: Some(previous.revision),
                status: super::super::code_review::Status::Partial,
                scope: vec!["entry point".into()],
                gaps: vec!["guards remain".into()],
                uncertainties: Vec::new(),
            },
        )
        .unwrap();
        assert!(resumed.current);
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }

    #[test]
    fn source_finding_is_revision_bound_and_does_not_copy_source() {
        let codebase = tempfile::tempdir().unwrap();
        std::fs::write(codebase.path().join("app.rs"), "sensitive fixture line\n").unwrap();
        std::fs::write(codebase.path().join("guard.rs"), "guard fixture line\n").unwrap();
        for args in [
            vec!["init", "-b", "main"],
            vec!["config", "user.email", "fixture@example.invalid"],
            vec!["config", "user.name", "Fixture"],
            vec!["add", "app.rs", "guard.rs"],
            vec!["commit", "-m", "fixture"],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(args)
                    .current_dir(codebase.path())
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        let project = uuid::Uuid::new_v4().to_string();
        let mut store = Store::open(&project).unwrap();
        let snapshot = Snapshot {
            schema_version: 1,
            id: "snapshot".into(),
            project_id: project.clone(),
            profile_sha256: "profile".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            codebase_revisions: vec![codebase_revision::capture_path(codebase.path())],
            instances: Vec::new(),
            coverage: Vec::new(),
            cases: Vec::new(),
            partial: false,
            alert_status: "local".into(),
        };
        store.save_snapshot(&snapshot).unwrap();
        let review_revision = start_review(&store, &snapshot);
        let submission = Submission {
            schema_version: 1,
            finding_id: None,
            snapshot_id: snapshot.id.clone(),
            review_revision: review_revision.clone(),
            codebase: 0,
            path: "app.rs".into(),
            line: 1,
            line_sha256: Some(crate::digest(b"sensitive fixture line")),
            evidence: vec![SourceLocation {
                codebase: 0,
                review_revision,
                path: "guard.rs".into(),
                line: 1,
                line_sha256: crate::digest(b"guard fixture line"),
            }],
            category: "credential exposure".into(),
            title: "Credential in configuration".into(),
            severity: Severity::High,
            disposition: Disposition::Actionable,
            analysis: "The build configuration embeds a credential.".into(),
            impact: "The credential may be exposed to readers.".into(),
            recommendation: "Remove and rotate the credential.".into(),
        };
        let finding = record(&store, submission.clone()).unwrap();
        assert!(finding.current);
        let mut mismatch = submission.clone();
        mismatch.line_sha256 = Some(crate::digest(b"different line"));
        assert!(record(&store, mismatch).is_err());
        let mut stale = submission.clone();
        stale.snapshot_id = "previous-scan".into();
        assert!(record(&store, stale).is_err());
        let mut bad_evidence = submission.clone();
        bad_evidence.evidence[0].line = 999;
        assert!(record(&store, bad_evidence).is_err());
        let mut duplicate = submission.clone();
        duplicate.evidence.push(duplicate.evidence[0].clone());
        assert!(record(&store, duplicate).is_err());
        let stored = serde_json::to_string(&finding).unwrap();
        assert!(!stored.contains("sensitive fixture line"));
        assert!(!stored.contains("guard fixture line"));
        let mut report = crate::output::morning_report(&snapshot, &store, "cyber").unwrap();
        crate::output::prepare_report_paths(&mut report, &store).unwrap();
        let markdown = crate::output::morning_markdown(&report).unwrap();
        assert!(markdown.contains("Credential in configuration"));
        assert!(!markdown.contains("sensitive fixture line"));
        assert!(current(&store, &snapshot).unwrap()[0].current);
        let mut revised = submission.clone();
        revised.title = "Updated assessment".into();
        let repeated = record(&store, revised).unwrap();
        assert_eq!(repeated.id, finding.id);
        assert_eq!(
            current(&store, &snapshot).unwrap()[0].finding.title,
            "Updated assessment"
        );
        let mut moved = submission.clone();
        moved.finding_id = Some(finding.id.clone());
        moved.path = "guard.rs".into();
        moved.line_sha256 = Some(crate::digest(b"guard fixture line"));
        moved.evidence.clear();
        moved.disposition = Disposition::Resolved;
        store
            .set_meta("code_finding_latest:unrelated", "invalid fixture")
            .unwrap();
        let resolved = record(&store, moved.clone()).unwrap();
        store
            .connection
            .execute(
                "DELETE FROM meta WHERE key = ?1",
                ["code_finding_latest:unrelated"],
            )
            .unwrap();
        assert_eq!(resolved.id, finding.id);
        assert_eq!(current(&store, &snapshot).unwrap().len(), 1);
        moved.finding_id = Some("CODE-does-not-exist".into());
        assert!(record(&store, moved).is_err());
        let mut private = submission.clone();
        private.impact = "password=synthetic-value".into();
        assert!(record(&store, private.clone()).is_err());
        private.impact = "The credential may be exposed to readers.".into();
        private.path = ".env".into();
        std::fs::write(codebase.path().join(".env"), "private\n").unwrap();
        assert!(record(&store, private).is_err());
        std::fs::write(codebase.path().join("guard.rs"), "changed guard\n").unwrap();
        assert!(!current(&store, &snapshot).unwrap()[0].current);
        std::fs::write(codebase.path().join("guard.rs"), "guard fixture line\n").unwrap();
        std::fs::write(codebase.path().join("app.rs"), "changed\n").unwrap();
        assert!(!current(&store, &snapshot).unwrap()[0].current);
        std::fs::remove_file(codebase.path().join("guard.rs")).unwrap();
        let mut next = snapshot.clone();
        next.id = "after-removal".into();
        next.codebase_revisions = vec![codebase_revision::capture_path(codebase.path())];
        store.save_snapshot(&next).unwrap();
        let mut removed = submission.clone();
        removed.snapshot_id = next.id.clone();
        removed.review_revision = start_review(&store, &next);
        removed.finding_id = Some(finding.id.clone());
        removed.path = "guard.rs".into();
        removed.line_sha256 = None;
        removed.evidence.clear();
        removed.disposition = Disposition::Resolved;
        let removed = record(&store, removed).unwrap();
        assert_eq!(removed.id, finding.id);
        assert!(removed.source_removed);
        assert!(current(&store, &next).unwrap()[0].current);
        std::fs::write(codebase.path().join("guard.rs"), "restored\n").unwrap();
        assert!(!current(&store, &next).unwrap()[0].current);
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }

    #[test]
    fn non_git_findings_track_the_visible_source_scope() {
        let codebase = tempfile::tempdir().unwrap();
        std::fs::write(codebase.path().join("app.rs"), "fn entry() {}\n").unwrap();
        std::fs::write(codebase.path().join("guard.rs"), "fn guard() {}\n").unwrap();
        std::fs::write(codebase.path().join(".gitignore"), "ignored.rs\n").unwrap();
        std::fs::write(codebase.path().join("ignored.rs"), "fn ignored() {}\n").unwrap();
        let project = uuid::Uuid::new_v4().to_string();
        let mut store = Store::open(&project).unwrap();
        let snapshot = Snapshot {
            schema_version: 1,
            id: "non-git-snapshot".into(),
            project_id: project.clone(),
            profile_sha256: "profile".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            codebase_revisions: vec![codebase_revision::capture_path(codebase.path())],
            instances: Vec::new(),
            coverage: Vec::new(),
            cases: Vec::new(),
            partial: false,
            alert_status: "local".into(),
        };
        store.save_snapshot(&snapshot).unwrap();
        let review_revision = start_review(&store, &snapshot);
        let submission = Submission {
            schema_version: 1,
            finding_id: None,
            snapshot_id: snapshot.id.clone(),
            review_revision,
            codebase: 0,
            path: "app.rs".into(),
            line: 1,
            line_sha256: Some(crate::digest(b"fn entry() {}")),
            evidence: Vec::new(),
            category: "authorization".into(),
            title: "Missing check".into(),
            severity: Severity::High,
            disposition: Disposition::Review,
            analysis: "A guard may be missing.".into(),
            impact: "Access may be unauthorized.".into(),
            recommendation: "Review the guard.".into(),
        };
        let mut ignored = submission.clone();
        ignored.path = "ignored.rs".into();
        ignored.line_sha256 = Some(crate::digest(b"fn ignored() {}"));
        assert!(!record(&store, ignored).unwrap().current);
        std::fs::write(codebase.path().join("guard.rs"), "fn changed_guard() {}\n").unwrap();
        assert!(record(&store, submission.clone()).is_err());
        std::fs::write(codebase.path().join("guard.rs"), "fn guard() {}\n").unwrap();
        let finding = record(&store, submission).unwrap();
        assert!(finding.current);
        store
            .connection
            .execute(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 10001)
             INSERT INTO meta(key, value) SELECT 'code_finding:history:' || i, ?1 FROM n",
                [serde_json::to_string(&finding).unwrap()],
            )
            .unwrap();
        let findings = current(&store, &snapshot).unwrap();
        assert!(
            findings
                .iter()
                .find(|entry| entry.id == finding.id)
                .unwrap()
                .current
        );
        std::fs::write(
            codebase.path().join("guard.rs"),
            "fn guard() { /* changed */ }\n",
        )
        .unwrap();
        assert!(
            !current(&store, &snapshot)
                .unwrap()
                .iter()
                .find(|entry| entry.id == finding.id)
                .unwrap()
                .current
        );
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }

    #[test]
    fn untracked_git_source_is_fingerprinted_and_reopened_on_change() {
        let codebase = tempfile::tempdir().unwrap();
        std::fs::write(codebase.path().join("tracked.rs"), "fn tracked() {}\n").unwrap();
        for args in [
            vec!["init", "-b", "main"],
            vec!["config", "user.email", "fixture@example.invalid"],
            vec!["config", "user.name", "Fixture"],
            vec!["add", "tracked.rs"],
            vec!["commit", "-m", "fixture"],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(args)
                    .current_dir(codebase.path())
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        std::fs::write(codebase.path().join("untracked.rs"), "fn pending() {}\n").unwrap();
        let project = uuid::Uuid::new_v4().to_string();
        let mut store = Store::open(&project).unwrap();
        let snapshot = Snapshot {
            schema_version: 1,
            id: "untracked".into(),
            project_id: project.clone(),
            profile_sha256: "profile".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            codebase_revisions: vec![codebase_revision::capture_path(codebase.path())],
            instances: Vec::new(),
            coverage: Vec::new(),
            cases: Vec::new(),
            partial: false,
            alert_status: "local".into(),
        };
        store.save_snapshot(&snapshot).unwrap();
        let review_revision = start_review(&store, &snapshot);
        let submission = Submission {
            schema_version: 1,
            finding_id: None,
            snapshot_id: snapshot.id.clone(),
            review_revision,
            codebase: 0,
            path: "untracked.rs".into(),
            line: 1,
            line_sha256: Some(crate::digest(b"fn pending() {}")),
            evidence: Vec::new(),
            category: "authorization".into(),
            title: "Check a guard".into(),
            severity: Severity::High,
            disposition: Disposition::Review,
            analysis: "A guard requires review.".into(),
            impact: "Access may be unauthorized.".into(),
            recommendation: "Review the guard.".into(),
        };
        assert!(record(&store, submission).unwrap().current);
        assert!(current(&store, &snapshot).unwrap()[0].current);
        std::fs::write(
            codebase.path().join("untracked.rs"),
            "fn pending() { /* changed */ }\n",
        )
        .unwrap();
        assert!(!current(&store, &snapshot).unwrap()[0].current);
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }
}
