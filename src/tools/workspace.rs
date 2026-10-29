//! `tools workspace init`: the folder layout the skill uses to keep a monitor's artifacts.
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct WorkspaceLayout {
    pub schema_version: u32,
    pub workspace: PathBuf,
    pub monitor: String,
    pub profile: PathBuf,
    pub profile_exists: bool,
    pub decisions: PathBuf,
    /// Directory of today's run; `raw/` receives the fetched responses.
    pub run: PathBuf,
    pub directories: BTreeMap<&'static str, PathBuf>,
    pub created: Vec<PathBuf>,
}

pub fn init(workspace: &Path, monitor: &str, day: &str) -> Result<WorkspaceLayout> {
    let valid_name = monitor
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && monitor.len() <= 64
        && monitor.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
    if !valid_name {
        bail!("monitor name must match [a-z0-9][a-z0-9-]* and have at most 64 characters");
    }
    if chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d").is_err() {
        bail!("run day must be YYYY-MM-DD");
    }
    let root = workspace.join("monitors").join(monitor);
    let run = root.join("runs").join(day);
    let directories = BTreeMap::from([
        ("shared_notes", workspace.join("notes")),
        ("decisions", root.join("decisions")),
        ("notes", root.join("notes")),
        ("sources", root.join("sources")),
        ("reports", root.join("reports")),
        ("run_raw", run.join("raw")),
    ]);
    let mut created = Vec::new();
    for directory in directories.values() {
        if fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!("{} is a symbolic link", directory.display());
        }
        if !directory.is_dir() {
            fs::create_dir_all(directory)?;
            created.push(directory.clone());
        }
    }
    let profile = root.join("vulnbell.yaml");
    Ok(WorkspaceLayout {
        schema_version: 1,
        workspace: workspace.to_path_buf(),
        monitor: monitor.to_owned(),
        profile_exists: profile.is_file(),
        profile,
        decisions: root.join("decisions").join("research.json"),
        run,
        directories,
        created,
    })
}
