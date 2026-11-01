//! Bounded, read-only checks of explicit source references.
use crate::{codebase_revision, store::Store};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::Read;

const FILE_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CitationBatch {
    pub schema_version: u32,
    pub citations: Vec<Citation>,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    /// Zero-based index in the scan's codebase_revisions array.
    pub codebase: usize,
    pub path: String,
    /// One-based line; its SHA-256 excludes the line ending.
    pub line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationStatus {
    LinePresent,
    Matched,
    Mismatch,
    Unavailable,
}

#[derive(Serialize)]
pub struct CitationResult {
    pub citation: Citation,
    pub status: CitationStatus,
    pub actual_line_sha256: Option<String>,
}

#[derive(Serialize)]
pub struct CitationReport {
    pub schema_version: u32,
    pub case_id: String,
    pub facts_sha256: String,
    pub snapshot_id: String,
    pub codebase_revisions: Vec<codebase_revision::CodebaseRevision>,
    pub complete: bool,
    pub citations: Vec<CitationResult>,
    pub limitations: &'static str,
}

pub fn check(store: &Store, case_id: &str, batch: CitationBatch) -> Result<CitationReport> {
    if batch.schema_version != 1 || !(1..=100).contains(&batch.citations.len()) {
        bail!("use schema_version 1 and 1..100 citations");
    }
    store.ensure_codebases_current()?;
    let snapshot = store.latest()?;
    let active: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
        [case_id],
        |row| row.get(0),
    )?;
    if !active {
        bail!("citation checks require an active case");
    }
    let case = store.case(case_id)?;
    if snapshot.codebase_revisions.is_empty()
        || !codebase_revision::same_revisions(
            &snapshot.codebase_revisions,
            &case.codebase_revisions,
        )
    {
        bail!("case has no current codebase context; rescan before checking citations");
    }
    let mut results = Vec::with_capacity(batch.citations.len());
    for citation in batch.citations {
        if citation.line == 0 || citation.path.is_empty() || citation.path.len() > 4096 {
            bail!("each citation needs a relative path and a positive line number");
        }
        if let Some(hash) = &citation.line_sha256
            && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            bail!("line_sha256 must be a SHA-256 hex digest");
        }
        let root = snapshot
            .codebase_revisions
            .get(citation.codebase)
            .context("codebase index is outside the scan scope")?;
        let actual = line_hash(&root.codebase, &citation.path, citation.line).ok();
        let status = match (&actual, &citation.line_sha256) {
            (None, _) => CitationStatus::Unavailable,
            (Some(_), None) => CitationStatus::LinePresent,
            (Some(actual), Some(expected)) if actual.eq_ignore_ascii_case(expected) => {
                CitationStatus::Matched
            }
            (Some(_), Some(_)) => CitationStatus::Mismatch,
        };
        results.push(CitationResult {
            citation,
            status,
            actual_line_sha256: actual,
        });
    }
    store.ensure_codebases_current()?;
    let current = store.case(case_id)?;
    if current.facts_sha256 != case.facts_sha256
        || !codebase_revision::same_revisions(&current.codebase_revisions, &case.codebase_revisions)
    {
        bail!("case changed while checking citations; retry with current facts");
    }
    let complete = results.iter().all(|result| {
        matches!(
            result.status,
            CitationStatus::LinePresent | CitationStatus::Matched
        )
    });
    Ok(CitationReport {
        schema_version: 1,
        case_id: case.case_id,
        facts_sha256: case.facts_sha256,
        snapshot_id: snapshot.id,
        codebase_revisions: snapshot.codebase_revisions,
        complete,
        citations: results,
        limitations: "Checks current file and line existence and optional line hash only; it does not verify meaning, reachability or deployment. Ignored files, private paths, untracked dependency/build output and non-Git trees are not bound by the Git fingerprint. Output directories are excluded from citation checks.",
    })
}

fn line_hash(root: &str, path: &str, line: usize) -> Result<String> {
    let mut components = std::path::Path::new(path).components().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_some()
            && let std::path::Component::Normal(name) = component
            && crate::inventory::excluded_directory(&name.to_string_lossy())
        {
            bail!("dependency or build output is outside the reviewed codebase fingerprint");
        }
    }
    crate::discovery::checked_path(root, path)?;
    let file = crate::discovery::open_file(root, path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > FILE_LIMIT {
        bail!("source is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FILE_LIMIT || bytes.contains(&0) {
        bail!("source is not bounded text");
    }
    let text = std::str::from_utf8(&bytes)?;
    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
        bail!("private key material is excluded");
    }
    let selected = text.lines().nth(line - 1).context("line unavailable")?;
    Ok(crate::digest(selected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::line_hash;
    use std::fs;

    #[test]
    fn checks_bounded_text_without_following_private_paths() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        let root = canonical.to_str().unwrap();
        fs::write(dir.path().join("source.txt"), "first\r\nsecond\n").unwrap();
        assert_eq!(
            line_hash(root, "source.txt", 2).unwrap(),
            crate::digest(b"second")
        );
        assert!(line_hash(root, "source.txt", 3).is_err());
        assert!(line_hash(root, "../source.txt", 1).is_err());
        fs::write(dir.path().join(".env"), "secret").unwrap();
        assert!(line_hash(root, ".env", 1).is_err());
        fs::write(dir.path().join("binary.txt"), b"not\0text").unwrap();
        assert!(line_hash(root, "binary.txt", 1).is_err());
        fs::create_dir(dir.path().join("vendor")).unwrap();
        fs::write(
            dir.path().join("vendor/dependency.txt"),
            "outside fingerprint\n",
        )
        .unwrap();
        assert!(line_hash(root, "vendor/dependency.txt", 1).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("source.txt", dir.path().join("link.txt")).unwrap();
            assert!(line_hash(root, "link.txt", 1).is_err());
        }
    }
}
