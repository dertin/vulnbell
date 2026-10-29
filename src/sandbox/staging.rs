use super::TestInput;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STAGED_FILES: usize = 1000;

#[derive(Serialize)]
pub struct StagedFile {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: usize,
}
#[derive(Serialize)]
pub struct StagedBundle {
    pub schema_version: u32,
    pub files: Vec<StagedFile>,
    pub input: TestInput,
}

/// Copies only the reviewed allowlist. Never runs project tools or extracts archives on the host.
pub fn stage(source: &Path, files: &[PathBuf], directory: &Path) -> Result<StagedBundle> {
    if files.is_empty() || files.len() > MAX_STAGED_FILES {
        bail!("select 1..1000 reviewed files; whole-directory copies are not accepted");
    }
    let root = source
        .canonicalize()
        .context("source directory unavailable")?;
    if !root.is_dir() {
        bail!("source must be a directory");
    }
    if directory.try_exists()? || directory.is_symlink() {
        bail!("bundle directory must not exist; existing tests are never overwritten");
    }
    let mut archive = tar::Builder::new(Vec::new());
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0_usize;
    for relative in files {
        validate_path(relative)?;
        if !seen.insert(relative) {
            bail!("duplicate staged path");
        }
        let mut checked = root.clone();
        for component in relative.components() {
            checked.push(component);
            if fs::symlink_metadata(&checked)?.is_symlink() {
                bail!("staged paths must not contain symlinks");
            }
        }
        if checked.canonicalize()? != checked {
            bail!("staged path redirects outside its selected location");
        }
        let bytes = crate::read_limited(&checked, MAX_ARCHIVE_BYTES as u64)?;
        total = total
            .checked_add(bytes.len())
            .context("staging byte limit overflow")?;
        if total > MAX_ARCHIVE_BYTES {
            bail!("selected files exceed the 16 MiB archive limit");
        }
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        archive.append_data(&mut header, relative, bytes.as_slice())?;
        entries.push(StagedFile {
            path: relative.clone(),
            sha256: crate::digest(&bytes),
            bytes: bytes.len(),
        });
    }
    let bytes = archive.into_inner()?;
    if bytes.len() > MAX_ARCHIVE_BYTES {
        bail!("archive headers and files exceed the 16 MiB input limit");
    }
    let bundle = StagedBundle {
        schema_version: 1,
        files: entries,
        input: TestInput {
            path: "inputs/project.tar".into(),
            name: "project.tar".into(),
            sha256: crate::digest(&bytes),
        },
    };
    // Build privately and publish only after the full selection has passed validation.
    let parent = directory
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::tempdir_in(parent)?;
    crate::atomic_write(&temporary.path().join(&bundle.input.path), &bytes)?;
    crate::atomic_write(
        &temporary.path().join("bundle.json"),
        &serde_json::to_vec_pretty(&bundle)?,
    )?;
    fs::create_dir(directory).context("cannot create a new bundle directory")?;
    // Keep the destination private even on systems where directory defaults are permissive.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    fs::rename(temporary.path().join("inputs"), directory.join("inputs"))?;
    fs::rename(
        temporary.path().join("bundle.json"),
        directory.join("bundle.json"),
    )?;
    Ok(bundle)
}

fn validate_path(path: &Path) -> Result<()> {
    let value = path.to_str().context("selected paths must use UTF-8")?;
    if value.len() > 240
        || value.contains(['\\', ':'])
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        bail!("select relative file paths without traversal or platform prefixes");
    }
    for part in path.components() {
        let name = part
            .as_os_str()
            .to_str()
            .context("invalid filename")?
            .to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || name.ends_with('.')
            || name == ".env"
            || name.starts_with(".env.")
            || [
                ".git",
                ".ssh",
                ".aws",
                ".kube",
                ".config",
                ".npmrc",
                ".netrc",
                ".pypirc",
                "credentials",
                "credentials.json",
                "id_rsa",
                "id_ed25519",
            ]
            .contains(&name.as_str())
            || [".pem", ".key", ".p12", ".pfx"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            bail!("selected path contains a private or unsupported filename; review the allowlist");
        }
    }
    Ok(())
}
