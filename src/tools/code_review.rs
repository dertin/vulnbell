use crate::{codebase_revision, store::Store};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(crate) mod automation;

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    InProgress,
    Partial,
    Complete,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub codebase: usize,
    /// Last recorded review revision, or null when starting a new review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_revision: Option<String>,
    pub status: Status,
    /// Concise reviewed areas or next work units, without source snippets or secrets.
    pub scope: Vec<String>,
    /// Unreviewed areas and their reason, without source snippets or secrets.
    pub gaps: Vec<String>,
    /// Unresolved reachability or context questions within the reviewed scope.
    #[serde(default)]
    pub uncertainties: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct Review {
    pub revision: String,
    pub submission: Submission,
    pub indexed_languages: Vec<String>,
    pub codebase_revision: codebase_revision::CodebaseRevision,
    pub source_fingerprint: Option<String>,
    pub recorded_at: String,
    pub current: bool,
}

fn key(root: &str) -> String {
    format!("code_review:{}", crate::digest(root.as_bytes()))
}

fn current_reviews(
    store: &Store,
    snapshot: &crate::model::Snapshot,
    deadline: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<Option<Review>>> {
    (0..snapshot.codebase_revisions.len())
        .map(|index| {
            if chrono::Utc::now() >= deadline {
                bail!("independent code review budget expired; progress is retained");
            }
            current_one(store, snapshot, index)
        })
        .collect()
}

pub fn record(store: &Store, submission: Submission) -> Result<Review> {
    record_until(store, submission, None)
}

fn record_until(
    store: &Store,
    mut submission: Submission,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Review> {
    if submission.schema_version != 1
        || submission.scope.len() > 100
        || submission.gaps.len() > 100
        || submission.uncertainties.len() > 100
        || submission
            .scope
            .iter()
            .chain(&submission.gaps)
            .chain(&submission.uncertainties)
            .any(|item| !super::code_findings::text_valid(item, 500))
        || (submission.status == Status::Complete
            && (submission.scope.is_empty() || !submission.gaps.is_empty()))
        || (submission.status == Status::Partial && submission.gaps.is_empty())
    {
        bail!("invalid code review: supply bounded scope and gaps consistent with its status");
    }
    let _lock = store.lock()?;
    store.ensure_codebases_current()?;
    let snapshot = store.latest()?;
    if snapshot.id != submission.snapshot_id {
        bail!("code review refers to a stale scan");
    }
    let revision = snapshot
        .codebase_revisions
        .get(submission.codebase)
        .context("codebase index outside the monitored scope")?
        .clone();
    let key = key(&revision.codebase);
    let previous = store
        .meta(&key)?
        .map(|value| serde_json::from_str::<Review>(&value))
        .transpose()?;
    if previous.as_ref().map(|review| review.revision.as_str())
        != submission.previous_revision.as_deref()
    {
        bail!("code review changed; reload its revision before recording progress");
    }
    let restarting = submission.status == Status::InProgress
        && submission.scope.is_empty()
        && submission.gaps.is_empty()
        && submission.uncertainties.is_empty();
    let source_fingerprint = crate::runners::codebase::source_fingerprint(&revision.codebase).ok();
    if source_fingerprint.is_none() {
        if submission.status == Status::Complete {
            bail!(
                "visible source could not be fingerprinted consistently; keep the review partial"
            );
        }
        let gap = "Visible source fingerprint unavailable or changed";
        if !submission.gaps.iter().any(|item| item == gap) {
            if submission.gaps.len() >= 100 {
                bail!("no room to record the source fingerprint gap");
            }
            submission.gaps.push(gap.into());
        }
    }
    if !restarting && let Some(previous) = &previous {
        let indeterminate = previous.source_fingerprint.is_none()
            && source_fingerprint.is_none()
            && submission.status != Status::Complete;
        if !codebase_revision::same_revisions(
            std::slice::from_ref(&previous.codebase_revision),
            std::slice::from_ref(&revision),
        ) || (!indeterminate
            && (previous.source_fingerprint.is_none()
                || previous.source_fingerprint != source_fingerprint))
        {
            bail!("source changed since review began; restart with an empty in-progress review");
        }
    }
    if submission.status == Status::Complete && previous.is_none() {
        bail!("start an in-progress review before recording completion");
    }
    let indexed_languages = if submission.status == Status::Complete {
        let roots: Vec<String> = snapshot
            .codebase_revisions
            .iter()
            .map(|item| item.codebase.clone())
            .collect();
        let seconds = deadline
            .map(|end| (end - chrono::Utc::now()).num_seconds().max(0) as u64)
            .unwrap_or(20)
            .min(20);
        if seconds == 0 {
            bail!("independent code review budget expired; progress is retained");
        }
        crate::runners::codebase::graph::indexed_languages_with_timeout(
            Path::new(&revision.codebase),
            &roots,
            seconds,
        )?
    } else {
        Vec::new()
    };
    if submission.status == Status::Complete
        && crate::runners::codebase::source_fingerprint(&revision.codebase).ok()
            != source_fingerprint
    {
        bail!("source changed while checking CodeGraph; restart the review");
    }
    store.ensure_codebases_current()?;
    if deadline.is_some_and(|end| chrono::Utc::now() >= end) {
        bail!("independent code review budget expired; progress is retained");
    }
    let current = source_fingerprint.is_some();
    let review = Review {
        revision: uuid::Uuid::new_v4().to_string(),
        submission,
        indexed_languages,
        source_fingerprint,
        codebase_revision: revision,
        recorded_at: crate::now(),
        current,
    };
    store.set_meta(&key, &serde_json::to_string(&review)?)?;
    Ok(review)
}

pub fn current(store: &Store, snapshot: &crate::model::Snapshot) -> Result<Vec<Review>> {
    let mut reviews = Vec::new();
    for index in 0..snapshot.codebase_revisions.len() {
        if let Some(review) = current_one(store, snapshot, index)? {
            reviews.push(review);
        }
    }
    Ok(reviews)
}

pub(super) fn current_one(
    store: &Store,
    snapshot: &crate::model::Snapshot,
    index: usize,
) -> Result<Option<Review>> {
    let revision = snapshot
        .codebase_revisions
        .get(index)
        .context("codebase index outside the monitored scope")?;
    let Some(value) = store.meta(&key(&revision.codebase))? else {
        return Ok(None);
    };
    let mut review: Review = serde_json::from_str(&value)?;
    review.submission.codebase = index;
    review.current = codebase_revision::same_revisions(
        std::slice::from_ref(&review.codebase_revision),
        std::slice::from_ref(revision),
    ) && codebase_revision::compare(std::slice::from_ref(revision))
        .first()
        .is_some_and(|comparison| comparison.matches)
        && review.source_fingerprint.as_ref().is_some_and(|expected| {
            crate::runners::codebase::source_fingerprint(&revision.codebase)
                .is_ok_and(|actual| &actual == expected)
        });
    Ok(Some(review))
}
