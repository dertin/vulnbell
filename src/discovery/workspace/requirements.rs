use super::{INCLUDE_GUARD, checked_path, open_file, requirements_file, stamp};
use crate::store::Store;
use anyhow::{Result, bail};
use rusqlite::params;
use std::{collections::BTreeSet, io::Read, path::Path};

fn local_archive(line: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        ".zip",
        ".whl",
        ".tar.bz2",
        ".tbz",
        ".tar.gz",
        ".tgz",
        ".tar",
        ".tar.xz",
        ".txz",
        ".tlz",
        ".tar.lz",
        ".tar.lzma",
    ];
    line.split_whitespace().any(|word| {
        let path = word.split(';').next().unwrap_or_default();
        let path = path.trim_matches(['\'', '"']).to_ascii_lowercase();
        EXTENSIONS.iter().any(|extension| {
            path.match_indices(extension).any(|(offset, _)| {
                let suffix = &path[offset + extension.len()..];
                suffix.is_empty() || suffix.starts_with('[')
            })
        })
    })
}

/// Close the agent boundary until all codebase directories have been classified.
pub(in crate::discovery) fn sync_include_guard(store: &Store, scope: &str) -> Result<bool> {
    let unfinished: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM discovery_walk WHERE scope=?1 AND state='pending')",
        [scope],
        |row| row.get(0),
    )?;
    if unfinished {
        return Ok(false);
    }
    let blocked = blocked_requirement_roots(store, scope)?;
    let roots: Vec<String> = store
        .connection
        .prepare("SELECT root FROM discovery_walk WHERE scope=?1 AND path=''")?
        .query_map([scope], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let transaction = store.connection.unchecked_transaction()?;
    for root in roots {
        if blocked.contains(&root) {
            transaction.execute(
                "DELETE FROM discovery_packages WHERE file_id IN (SELECT id FROM discovery_files WHERE scope=?1 AND root=?2)",
                params![scope, root],
            )?;
            transaction.execute(
                "UPDATE discovery_files SET state='unavailable',offset=0,reason=?3 WHERE scope=?1 AND root=?2 AND state IN ('pending','done')",
                params![scope, root, INCLUDE_GUARD],
            )?;
        } else {
            transaction.execute(
                "UPDATE discovery_files SET state='pending',offset=0,reason='' WHERE scope=?1 AND root=?2 AND state='unavailable' AND reason=?3",
                params![scope, root, INCLUDE_GUARD],
            )?;
        }
    }
    transaction.commit()?;
    Ok(true)
}

/// Included or local sources can have any name; keep the codebase local when scope is uncertain.
pub(super) fn blocked_requirement_roots(store: &Store, scope: &str) -> Result<BTreeSet<String>> {
    let mut blocked: BTreeSet<String> = store
        .connection
        .prepare("SELECT DISTINCT root FROM discovery_walk WHERE scope=?1 AND state='unavailable'")?
        .query_map([scope], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut query = store.connection.prepare(
        "SELECT root,path,state FROM discovery_files WHERE scope=?1 AND state<>'removed' AND (lower(path) LIKE '%requirements%.txt' OR lower(path) LIKE '%requirements%.in' OR lower(path) LIKE '%constraints%.txt' OR lower(path) LIKE '%constraints%.in') ORDER BY root,path",
    )?;
    let files: Vec<(String, String, String)> = query
        .query_map([scope], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut budget = 1024 * 1024_u64;
    for (root, path, state) in files {
        let is_requirements = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(requirements_file);
        if !is_requirements || blocked.contains(&root) {
            continue;
        }
        if state == "excluded" {
            blocked.insert(root);
            continue;
        }
        let check = || -> Result<(bool, u64)> {
            let input = checked_path(&root, &path)?;
            let before = stamp(&input)?;
            let mut contents = Vec::new();
            open_file(&root, &path)?
                .take(budget.saturating_add(1))
                .read_to_end(&mut contents)?;
            if contents.len() as u64 > budget {
                bail!("requirements preflight budget exceeded");
            }
            if stamp(&input)? != before {
                bail!("requirements changed during preflight");
            }
            let text = std::str::from_utf8(&contents)?;
            let mut logical = String::with_capacity(text.len());
            for line in text.lines() {
                if line
                    .trim_start_matches('\u{feff}')
                    .trim_start()
                    .starts_with('#')
                {
                    logical.push('\n');
                } else if let Some(line) = line.strip_suffix('\\') {
                    logical.push_str(line);
                } else {
                    logical.push_str(line);
                    logical.push('\n');
                }
            }
            let includes = logical.lines().any(|line| {
                let line = line.trim_start_matches('\u{feff}').trim_start();
                let comment = line.char_indices().find_map(|(index, character)| {
                    (character == '#'
                        && (index == 0 || line.as_bytes()[index - 1].is_ascii_whitespace()))
                    .then_some(index)
                });
                let line = line[..comment.unwrap_or(line.len())].trim_end();
                if line.starts_with('#') || line.is_empty() {
                    return false;
                }
                [
                    "-r",
                    "-c",
                    "-e",
                    "-i",
                    "-f",
                    "--requirement",
                    "--constraint",
                    "--editable",
                    "--index-url",
                    "--extra-index-url",
                    "--no-index",
                    "--find-links",
                    ".",
                    "/",
                    "~",
                    "file:",
                    "\\\\",
                ]
                .iter()
                .any(|option| line.starts_with(option))
                    || line.contains('@')
                    || line.contains("://")
                    || line.contains("${")
                    || line.contains('/')
                    || line.contains('\\')
                    || line.as_bytes().get(1) == Some(&b':')
                    || local_archive(line)
            });
            Ok((includes, contents.len() as u64))
        };
        match check() {
            Ok((includes, size)) => {
                budget = budget.saturating_sub(size);
                if includes {
                    blocked.insert(root);
                }
            }
            Err(_) => {
                blocked.insert(root);
            }
        }
    }
    if !blocked.is_empty() {
        blocked = store
            .connection
            .prepare("SELECT root FROM discovery_walk WHERE scope=?1 AND path=''")?
            .query_map([scope], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
    }
    Ok(blocked)
}
