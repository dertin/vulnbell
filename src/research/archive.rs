use super::{ArchiveEcosystem, ArtifactEvidence, InstalledArchiveEvidence};
use crate::model::{Instance, Origin, Snapshot};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashSet,
    io::Read,
    path::{Component, Path},
};

const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 20_000;

pub(super) fn matches_lock(
    evidence: &InstalledArchiveEvidence,
    instance: &Instance,
    artifact: &ArtifactEvidence,
) -> bool {
    let Some(purl) = instance
        .purl
        .as_deref()
        .and_then(|value| value.parse::<packageurl::PackageUrl<'_>>().ok())
    else {
        return false;
    };
    if instance.origin != Origin::Locked || instance.resolved_version.is_none() {
        return false;
    }
    match evidence.ecosystem {
        ArchiveEcosystem::Cargo => {
            purl.ty() == "cargo"
                && purl.namespace().is_none()
                && instance
                    .provenance
                    .resolution
                    .as_deref()
                    .is_some_and(|source| {
                        [
                            "registry+https://github.com/rust-lang/crates.io-index",
                            "sparse+https://index.crates.io/",
                        ]
                        .contains(&source)
                    })
                && instance.provenance.artifact_integrity.as_deref() == Some(&artifact.sha256)
        }
        ArchiveEcosystem::Npm => {
            purl.ty() == "npm"
                && instance
                    .provenance
                    .artifact_integrity
                    .as_deref()
                    .is_some_and(|s| s.split_whitespace().any(|part| part.starts_with("sha512-")))
        }
    }
}

pub(super) fn verify_content(
    artifact: &ArtifactEvidence,
    installed: &InstalledArchiveEvidence,
    snapshot: &Snapshot,
    store: &crate::store::Store,
) -> Result<HashSet<String>> {
    let instance = snapshot
        .instances
        .iter()
        .find(|item| item.id == artifact.instance_id)
        .context("archive instance is missing")?;
    if !matches_lock(installed, instance, artifact) {
        bail!("archive is not bound to a supported lockfile");
    }
    let purl: packageurl::PackageUrl<'_> = instance
        .purl
        .as_deref()
        .context("archive package identity is missing")?
        .parse()?;
    let package = purl.namespace().map_or_else(
        || purl.name().to_owned(),
        |ns| format!("{ns}/{}", purl.name()),
    );
    let version = instance
        .resolved_version
        .as_deref()
        .context("archive version is missing")?;
    let revision = snapshot
        .codebase_revisions
        .get(artifact.codebase)
        .context("archive codebase is missing")?;
    let root = &revision.codebase;
    crate::discovery::checked_path(root, &installed.scope.root)?;
    if installed.ecosystem == ArchiveEcosystem::Npm {
        let lock = instance
            .provenance
            .path
            .as_deref()
            .context("npm lock path is missing")?;
        let expected = Path::new(lock)
            .parent()
            .context("npm lock parent is missing")?
            .join(
                instance
                    .provenance
                    .resolution
                    .as_deref()
                    .context("npm package path is missing")?,
            );
        if expected != Path::new(&installed.scope.root) {
            bail!("npm installation does not match the lockfile path");
        }
    }
    let archive_root = super::validation::artifact_root(artifact, snapshot, store)?;
    if installed.ecosystem == ArchiveEcosystem::Npm {
        let file = crate::discovery::open_file(&archive_root, &artifact.path)?;
        let mut hash = Sha512::new();
        let mut reader = file.take(MAX_BYTES + 1);
        let mut count = 0_u64;
        let mut buffer = [0u8; 65536];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            count += read as u64;
            hash.update(&buffer[..read]);
        }
        if count > MAX_BYTES {
            bail!("archive exceeds the size limit");
        }
        let expected = STANDARD.encode(hash.finalize());
        if !instance
            .provenance
            .artifact_integrity
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .any(|part| part.strip_prefix("sha512-") == Some(expected.as_str()))
        {
            bail!("npm archive integrity does not match the lockfile");
        }
    }
    let file = crate::discovery::open_file(&archive_root, &artifact.path)?;
    let decoder = flate2::read::MultiGzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);
    let prefix = match installed.ecosystem {
        ArchiveEcosystem::Cargo => format!("{package}-{version}/"),
        ArchiveEcosystem::Npm => "package/".to_owned(),
    };
    let mut names = HashSet::new();
    let mut roots = HashSet::new();
    let mut observed = Vec::new();
    let mut manifest = None;
    let mut total = 0_u64;
    let mut name_bytes = 0_usize;
    for (index, entry) in tar.entries()?.raw(true).enumerate() {
        let mut entry = entry?;
        if index >= MAX_FILES {
            bail!("archive exceeds the entry limit");
        }
        let padded_size = entry
            .size()
            .checked_add(511)
            .context("archive size overflow")?
            / 512
            * 512;
        total = total
            .checked_add(512)
            .and_then(|size| size.checked_add(padded_size))
            .context("archive size overflow")?;
        if total > MAX_BYTES {
            bail!("archive exceeds the expanded size limit");
        }
        let path = entry.path_bytes();
        let name = std::str::from_utf8(&path)?.to_owned();
        name_bytes = name_bytes
            .checked_add(name.len())
            .context("archive path overflow")?;
        if name.len() > 4096
            || name_bytes > 8 * 1024 * 1024
            || name.contains('\\')
            || name.chars().any(char::is_control)
        {
            bail!("archive contains an unsafe path");
        }
        let relative = name
            .strip_prefix(&prefix)
            .context("archive entry is outside the package root")?
            .trim_end_matches('/');
        if relative.is_empty() {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            bail!("invalid package root");
        }
        if relative.split('/').any(|part| {
            part.is_empty() || part == "." || part == ".." || crate::discovery::private_name(part)
        }) || Path::new(relative)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
            || !names.insert(relative.to_ascii_lowercase())
        {
            bail!("archive has unsafe or duplicate paths");
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            bail!("archive contains an unsupported entry");
        }
        roots.insert(relative.split('/').next().context("empty path")?.to_owned());
        let is_manifest = match installed.ecosystem {
            ArchiveEcosystem::Cargo => relative == "Cargo.toml",
            ArchiveEcosystem::Npm => relative == "package.json",
        };
        if is_manifest && entry.size() > 1024 * 1024 {
            bail!("package manifest exceeds the size limit");
        }
        let mut expected = Sha256::new();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 65536];
        let mut count = 0_u64;
        loop {
            let read = entry.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > entry.size() {
                bail!("invalid archive entry size");
            }
            expected.update(&buffer[..read]);
            if is_manifest {
                bytes.extend_from_slice(&buffer[..read]);
            }
        }
        if count != entry.size() {
            bail!("invalid archive entry size");
        }
        let path = Path::new(&installed.scope.root).join(relative);
        let path = path.to_str().context("installation path is not UTF-8")?;
        observed.push(super::installed::verify_file(
            root,
            path,
            count,
            expected.finalize().into(),
        )?);
        if is_manifest {
            manifest = Some(bytes);
        }
    }
    let mut tail = tar.into_inner();
    let mut count = 0_u64;
    let mut buffer = [0u8; 65536];
    loop {
        let read = tail.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if total
            .checked_add(512)
            .and_then(|size| size.checked_add(count))
            .is_none_or(|size| size > MAX_BYTES)
            || buffer[..read].iter().any(|byte| *byte != 0)
        {
            bail!("archive contains trailing data");
        }
    }
    let manifest = manifest.context("package manifest is missing")?;
    let (actual_name, actual_version) = match installed.ecosystem {
        ArchiveEcosystem::Cargo => {
            let value: toml::Value = toml::from_str(std::str::from_utf8(&manifest)?)?;
            (
                value
                    .get("package")
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                value
                    .get("package")
                    .and_then(|v| v.get("version"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
            )
        }
        ArchiveEcosystem::Npm => {
            let value: serde_json::Value = serde_json::from_slice(&manifest)?;
            (
                value
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                value
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
            )
        }
    };
    if actual_name.as_deref() != Some(&package) || actual_version.as_deref() != Some(version) {
        bail!("package manifest does not match the lockfile");
    }
    super::installed::verify_unchanged(root, &observed)?;
    Ok(roots)
}

#[cfg(test)]
mod tests;
