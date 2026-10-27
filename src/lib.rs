//! Deterministic inventory, evidence and execution contracts for VulnBell.
pub mod discovery;
pub mod engine;
pub mod identity;
pub mod impact;
pub mod inventory;
pub mod model;
pub mod network;
pub mod operations;
pub mod output;
pub mod process;
pub mod profile;
pub mod research;
pub mod runners;
pub mod sandbox;
pub mod scheduler;
pub mod skills;
pub mod sources;
pub mod store;
pub mod tools;
pub mod upstream;
pub mod vendor;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
/// Compact JSON with recursively sorted object keys, or `None` when `bytes` is not JSON.
/// Feeds may reorder keys between requests; hashing this form keeps identical content stable.
pub fn canonical_json(bytes: &[u8]) -> Option<Vec<u8>> {
    fn sorted(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let ordered: std::collections::BTreeMap<String, serde_json::Value> = map
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect();
                serde_json::Value::Object(ordered.into_iter().collect())
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(sorted).collect())
            }
            other => other,
        }
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    serde_json::to_vec(&sorted(value)).ok()
}
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
pub fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("cannot inspect input")?;
    if !metadata.is_file() || metadata.len() > limit {
        bail!("input must be a regular file under {limit} bytes");
    }
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        bail!("input changed type during open");
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("input exceeded size limit");
    }
    Ok(bytes)
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    if path.is_symlink() {
        bail!("refusing symlink output");
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub fn user_home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME")
            .filter(|path| !path.is_empty())
            .or_else(|| std::env::var_os("USERPROFILE").filter(|path| !path.is_empty()))
            .context("user home is unavailable; set HOME or USERPROFILE")?,
    ))
}

pub fn parse_yaml<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> std::result::Result<T, serde_saphyr::Error> {
    let mut options = serde_saphyr::Options::default();
    // Keep parser budgets and duplicate-key rejection; never echo source snippets into logs.
    options.with_snippet = false;
    options.reject_unsupported_tags = true;
    serde_saphyr::from_slice_with_options(bytes, options)
}
