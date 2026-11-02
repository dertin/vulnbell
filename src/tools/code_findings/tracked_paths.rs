use crate::{codebase_revision::RepositoryState, model::Snapshot};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::{Component, Path},
};

use super::Finding;

const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

pub(super) fn collect(
    snapshot: &Snapshot,
    findings: &[Finding],
) -> HashMap<usize, HashSet<String>> {
    let mut paths = HashMap::<usize, BTreeSet<String>>::new();
    for finding in findings {
        if !finding.source_removed {
            paths
                .entry(finding.finding.codebase)
                .or_default()
                .insert(finding.finding.path.clone());
        }
        for citation in &finding.finding.evidence {
            paths
                .entry(citation.codebase)
                .or_default()
                .insert(citation.path.clone());
        }
    }
    paths
        .into_iter()
        .filter_map(|(index, paths)| {
            let root = snapshot.codebase_revisions.get(index)?;
            if root.state != RepositoryState::Git {
                return None;
            }
            Some((
                index,
                tracked_in_batches(&root.codebase, paths.into_iter().collect()),
            ))
        })
        .collect()
}

fn tracked_in_batches(root: &str, paths: Vec<String>) -> HashSet<String> {
    let mut tracked = HashSet::new();
    let mut batch = Vec::new();
    let mut bytes = 0_usize;
    for path in paths {
        let size = path.len().saturating_add(1);
        if !batch.is_empty() && bytes.saturating_add(size) > MAX_ARGUMENT_BYTES {
            tracked.extend(tracked_batch(root, &batch));
            batch.clear();
            bytes = 0;
        }
        if size > MAX_ARGUMENT_BYTES {
            continue;
        }
        bytes += size;
        batch.push(path);
    }
    if !batch.is_empty() {
        tracked.extend(tracked_batch(root, &batch));
    }
    tracked
}

fn tracked_batch(root: &str, paths: &[String]) -> HashSet<String> {
    let mut command = crate::codebase_revision::git_command(Path::new(root));
    command
        .arg("--literal-pathspecs")
        .args(["ls-files", "-z", "--"])
        .args(paths);
    let Ok(result) = crate::process::run_bounded(&mut command, 15, MAX_OUTPUT_BYTES) else {
        return HashSet::new();
    };
    if !result.success || (!result.stdout.is_empty() && result.stdout.last() != Some(&0)) {
        return HashSet::new();
    }
    let mut candidates = HashMap::<String, Vec<&str>>::new();
    for path in paths {
        if let Some(name) = normalized(path) {
            candidates.entry(name).or_default().push(path);
        }
    }
    result
        .stdout
        .split(|byte| *byte == 0)
        .filter_map(|entry| std::str::from_utf8(entry).ok())
        .filter_map(normalized)
        .filter_map(|name| candidates.get(&name))
        .flatten()
        .map(|path| (*path).to_owned())
        .collect()
}

fn normalized(path: &str) -> Option<String> {
    let parts: Option<Vec<_>> = Path::new(path)
        .components()
        .map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    let parts = parts?;
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[cfg(test)]
mod tests;
