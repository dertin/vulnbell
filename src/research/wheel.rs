use super::{ArtifactEvidence, InstalledScopeEvidence};
use crate::model::Snapshot;
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::Read,
    path::{Component, Path},
};

const MAX_FILES: usize = 20_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_METADATA: u64 = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TOTAL_NAME_BYTES: usize = 8 * 1024 * 1024;
mod structure;

/// Compare a wheel with the installed files without extracting or executing either.
pub(super) fn verify_content(
    artifact: &ArtifactEvidence,
    installed: &InstalledScopeEvidence,
    snapshot: &Snapshot,
    store: &crate::store::Store,
) -> Result<HashSet<String>> {
    if installed.root.is_empty() || installed.root.len() > MAX_PATH_BYTES {
        bail!("installed wheel root is invalid");
    }
    let revision = snapshot
        .codebase_revisions
        .get(artifact.codebase)
        .context("artifact codebase is outside the monitor")?;
    let root = &revision.codebase;
    let install_path = crate::discovery::checked_path(root, &installed.root)?;
    if !install_path.is_dir() {
        bail!("installed wheel root is not a directory");
    }
    let artifact_root = super::validation::artifact_root(artifact, snapshot, store)?;
    let mut wheel_file = crate::discovery::open_file(&artifact_root, &artifact.path)?;
    structure::validate(&mut wheel_file)?;
    let mut wheel =
        zip::unstable::read::ZipIterable::try_new(wheel_file, zip::read::Config::default())
            .context("invalid wheel archive")?
            .enforce_header_consistency(true);
    if wheel.is_empty() || wheel.len() > MAX_FILES {
        bail!("wheel exceeds the entry limit or is empty");
    }
    let mut names = HashSet::new();
    let mut total_name_bytes = 0_usize;
    let mut package_roots = HashSet::new();
    let mut dist_info = None::<String>;
    let mut metadata = None::<Vec<u8>>;
    let mut has_wheel = false;
    let mut has_record = false;
    let mut total = 0_u64;
    let mut observed_files = Vec::new();
    let entries = wheel.files()?;
    while let Some(entry) = entries.next() {
        let entry = entry.context("unsupported or corrupt wheel entry")?;
        let mut entry = entry.with_reader(entries.reader_mut(), zip::ZipReadOptions::new())?;
        let name = entry.name()?.into_owned();
        let raw_name =
            std::str::from_utf8(entry.name_raw()).context("wheel filename is not UTF-8")?;
        if raw_name != name {
            bail!("wheel filename has an ambiguous interpretation");
        }
        total_name_bytes = total_name_bytes
            .checked_add(name.len())
            .context("wheel path length overflow")?;
        if name.len() > MAX_PATH_BYTES || total_name_bytes > MAX_TOTAL_NAME_BYTES {
            bail!("wheel paths exceed the size limit");
        }
        if name.contains('\\')
            || name.chars().any(char::is_control)
            || entry.enclosed_name().is_none()
        {
            bail!("wheel contains an unsafe path");
        }
        let relative = Path::new(name.trim_end_matches('/'));
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            bail!("wheel contains a non-relative path");
        }
        let mode = entry.unix_mode().unwrap_or(0) & 0o170000;
        if mode != 0 && mode != 0o100000 && mode != 0o040000 {
            bail!("wheel contains a link or special file");
        }
        if !names.insert(name.trim_end_matches('/').to_ascii_lowercase()) {
            bail!("wheel contains duplicate or case-colliding paths");
        }
        if entry.is_dir() {
            continue;
        }
        let first = name.split('/').next().context("wheel entry has no name")?;
        if first.ends_with(".data") {
            bail!("wheel installation schemes with .data relocation are not supported");
        }
        if first.ends_with(".dist-info") {
            if dist_info.as_ref().is_some_and(|existing| existing != first) {
                bail!("wheel contains multiple distributions");
            }
            dist_info = Some(first.to_owned());
        } else {
            package_roots.insert(first.to_owned());
        }
        total = total
            .checked_add(entry.size())
            .context("wheel size overflow")?;
        if total > MAX_BYTES {
            bail!("wheel exceeds the expanded size limit");
        }
        let is_record = first.ends_with(".dist-info") && name == format!("{first}/RECORD");
        let installed_file = Path::new(&installed.root).join(relative);
        let installed_file = installed_file
            .to_str()
            .context("installed path is not UTF-8")?;
        let checked_file = crate::discovery::checked_path(root, installed_file)?;
        if is_record {
            if !checked_file.is_file() {
                bail!("installed RECORD is not a regular file");
            }
            has_record = true;
            continue;
        }
        let is_metadata = first.ends_with(".dist-info") && name == format!("{first}/METADATA");
        has_wheel |= first.ends_with(".dist-info") && name == format!("{first}/WHEEL");
        if is_metadata && entry.size() > MAX_METADATA {
            bail!("wheel metadata exceeds the size limit");
        }
        let mut expected = Sha256::new();
        let mut content = Vec::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut read_total = 0_u64;
        loop {
            let count = entry.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read_total += count as u64;
            if read_total > entry.size() {
                bail!("wheel entry exceeds its declared size");
            }
            expected.update(&buffer[..count]);
            if is_metadata {
                content.extend_from_slice(&buffer[..count]);
            }
        }
        if read_total != entry.size() {
            bail!("wheel entry has an invalid size");
        }
        observed_files.push(super::installed::verify_file(
            root,
            installed_file,
            read_total,
            expected.finalize().into(),
        )?);
        if is_metadata {
            metadata = Some(content);
        }
    }
    if !has_record || !has_wheel {
        bail!("wheel is missing RECORD or WHEEL metadata");
    }
    let metadata = std::str::from_utf8(metadata.as_deref().context("wheel is missing METADATA")?)?;
    let instance = snapshot
        .instances
        .iter()
        .find(|instance| instance.id == artifact.instance_id)
        .context("wheel instance missing")?;
    let purl: packageurl::PackageUrl<'_> = instance
        .purl
        .as_deref()
        .context("wheel requires verified package identity")?
        .parse()?;
    if purl.ty() != "pypi" || purl.namespace().is_some() {
        bail!("wheel requires a PyPI package identity");
    }
    let mut names = metadata
        .lines()
        .filter_map(|line| line.strip_prefix("Name:").map(str::trim));
    let name = names.next().context("wheel metadata is missing Name")?;
    let mut versions = metadata
        .lines()
        .filter_map(|line| line.strip_prefix("Version:").map(str::trim));
    let version = versions
        .next()
        .context("wheel metadata is missing Version")?;
    if names.next().is_some()
        || versions.next().is_some()
        || crate::identity::normalize_pypi(name) != crate::identity::normalize_pypi(purl.name())
        || version.parse::<pep508_rs::pep440_rs::Version>()?
            != instance
                .resolved_version
                .as_deref()
                .context("wheel version missing")?
                .parse::<pep508_rs::pep440_rs::Version>()?
    {
        bail!("wheel metadata does not match the monitored package and version");
    }
    super::installed::verify_unchanged(root, &observed_files)?;
    Ok(package_roots)
}

#[cfg(test)]
fn verify(
    artifact: &ArtifactEvidence,
    installed: &InstalledScopeEvidence,
    snapshot: &Snapshot,
    store: &crate::store::Store,
) -> Result<()> {
    let roots = verify_content(artifact, installed, snapshot, store)?;
    super::installed::verify_scope(artifact, installed, snapshot, &roots)
}

#[cfg(test)]
mod tests;
