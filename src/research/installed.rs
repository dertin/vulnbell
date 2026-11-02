use super::{ArtifactEvidence, InstalledScopeEvidence};
use crate::model::Snapshot;
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
};

const MAX_FILES: usize = 20_000;
const MAX_PATH_BYTES: usize = 4096;

pub(super) struct ObservedFile {
    path: String,
    length: u64,
    modified: std::time::SystemTime,
}

pub(super) fn verify_file(
    root: &str,
    path: &str,
    expected_size: u64,
    expected_digest: [u8; 32],
) -> Result<ObservedFile> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = crate::discovery::open_file(root, path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != expected_size {
        bail!("installed file differs from the archive");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > expected_size {
            bail!("installed file changed during verification");
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    if total != expected_size
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || digest.finalize().as_slice() != expected_digest
    {
        bail!("installed file differs from the archive or changed during verification");
    }
    Ok(ObservedFile {
        path: path.to_owned(),
        length: after.len(),
        modified: after.modified()?,
    })
}

pub(super) fn verify_unchanged(root: &str, files: &[ObservedFile]) -> Result<()> {
    for file in files {
        let current = crate::discovery::open_file(root, &file.path)?.metadata()?;
        if !current.is_file()
            || current.len() != file.length
            || current.modified()? != file.modified
        {
            bail!("installed files changed during verification");
        }
    }
    Ok(())
}

pub(super) fn verify_scope(
    artifact: &ArtifactEvidence,
    installed: &InstalledScopeEvidence,
    snapshot: &Snapshot,
    package_roots: &HashSet<String>,
) -> Result<()> {
    if installed.absent_paths.is_empty() || installed.absent_paths.len() > 32 {
        bail!("installed package evidence requires 1..32 absent paths or file patterns");
    }
    let root = &snapshot
        .codebase_revisions
        .get(artifact.codebase)
        .context("artifact codebase is outside the monitor")?
        .codebase;
    let source = &installed.scope_source;
    if source.line == 0
        || source.path.len() > MAX_PATH_BYTES
        || source.line_sha256.len() != 64
        || !source
            .line_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || crate::tools::citations::line_hash(root, &source.path, source.line)?
            != source.line_sha256
    {
        bail!("installed package build scope source is unavailable or has changed");
    }
    if installed.absent_paths.iter().any(|path| {
        path.split('/')
            .next()
            .is_none_or(|first| !package_roots.contains(first))
    }) {
        bail!("absent paths must be inside a package root present in the archive");
    }
    check_absent(root, installed)
}

fn check_absent(root: &str, installed: &InstalledScopeEvidence) -> Result<()> {
    let mut unique = HashSet::new();
    for name in &installed.absent_paths {
        if name.len() > MAX_PATH_BYTES
            || !unique.insert(name)
            || name.contains('\\')
            || name.chars().any(char::is_control)
        {
            bail!("absent paths must be distinct portable relative paths");
        }
        let parts: Vec<&str> = name.split('/').collect();
        if parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
        {
            bail!("absent path is not a safe relative path");
        }
        let path = Path::new(name);
        if path.as_os_str().is_empty()
            || path.components().any(|part| match part {
                Component::Normal(name) => name.to_str().is_none_or(crate::discovery::private_name),
                _ => true,
            })
        {
            bail!("absent path is not a safe relative path");
        }
        let pattern = parts.last().copied().context("absent path is empty")?;
        let has_pattern = pattern.contains(['*', '?']);
        if parts[..parts.len() - 1]
            .iter()
            .any(|part| part.contains(['*', '?', '[', ']']))
            || pattern.contains(['[', ']'])
            || (has_pattern
                && pattern
                    .chars()
                    .filter(|ch| !matches!(ch, '*' | '?'))
                    .count()
                    < 3)
        {
            bail!("wildcards are allowed only in a specific final path component");
        }
        let mut relative = PathBuf::from(&installed.root);
        let mut missing = false;
        let traversal = if has_pattern {
            path.parent().context("pattern needs a parent directory")?
        } else {
            path
        };
        for part in traversal.components() {
            relative.push(part.as_os_str());
            let current = Path::new(root).join(&relative);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    bail!("absent path contains a symlink")
                }
                Ok(_) => {
                    crate::discovery::checked_path(
                        root,
                        relative.to_str().context("path is not UTF-8")?,
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if has_pattern && !missing {
            let directory = crate::discovery::checked_path(
                root,
                relative.to_str().context("path is not UTF-8")?,
            )?;
            let matcher = globset::GlobBuilder::new(pattern)
                .literal_separator(true)
                .case_insensitive(cfg!(windows))
                .build()?
                .compile_matcher();
            for (index, entry) in std::fs::read_dir(directory)?.enumerate() {
                if index >= MAX_FILES {
                    bail!("absence check exceeds the directory entry limit");
                }
                let entry = entry?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .context("absence check cannot inspect a non-UTF-8 filename")?;
                if matcher.is_match(name) {
                    bail!("a path matching the absent pattern exists in the installed directory");
                }
            }
            missing = true;
        }
        if !missing {
            bail!("a path claimed absent exists in the installed directory");
        }
    }
    Ok(())
}
