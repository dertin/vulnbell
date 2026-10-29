//! Read-only identity of the workspaces included in a scan.
use crate::profile::Profile;
use anyhow::{Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::Command,
};

const MAX_CHANGED_FILES: usize = 10_000;
const MAX_CHANGED_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CHANGED_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryState {
    Git,
    NotGit,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkspaceRevision {
    pub workspace: String,
    pub state: RepositoryState,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    /// Changes excluding private paths, ignored files and submodule contents.
    pub dirty: Option<bool>,
    /// Hash of Git's status entries and changed files, without retaining names or contents.
    pub worktree_status_sha256: Option<String>,
    pub observed_at: String,
}

#[derive(Serialize, PartialEq, Eq)]
struct WorkspaceIdentity<'a> {
    workspace: &'a str,
    state: &'a RepositoryState,
    repository: Option<&'a str>,
    branch: Option<&'a str>,
    commit: Option<&'a str>,
    dirty: Option<bool>,
    worktree_status_sha256: Option<&'a str>,
}

impl WorkspaceRevision {
    fn identity(&self) -> WorkspaceIdentity<'_> {
        WorkspaceIdentity {
            workspace: &self.workspace,
            state: &self.state,
            repository: self.repository.as_deref(),
            branch: self.branch.as_deref(),
            commit: self.commit.as_deref(),
            dirty: self.dirty,
            worktree_status_sha256: self.worktree_status_sha256.as_deref(),
        }
    }
}

fn git_command(path: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(path).args([
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C");
    command
}

fn git(path: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    git_command(path).args(args).output()
}

fn text(output: &std::process::Output) -> Option<String> {
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn private_path(value: &str) -> Result<bool> {
    let path = Path::new(value);
    let mut private = false;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("invalid changed file path");
        };
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path encoding"))?;
        if name.chars().any(char::is_control) {
            bail!("invalid changed file path");
        }
        private |= crate::discovery::private_name(name);
    }
    Ok(private)
}

fn checked_relative(value: &str) -> Result<&Path> {
    if private_path(value)? {
        bail!("a changed file is private");
    }
    Ok(Path::new(value))
}

fn git_path(workspace: &Path, name: &str) -> Result<PathBuf> {
    let output = git(
        workspace,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    )?;
    let value = text(&output).ok_or_else(|| anyhow::anyhow!("Git metadata is unavailable"))?;
    Ok(PathBuf::from(value))
}

fn git_worktree_config(workspace: &Path) -> Result<Vec<(&'static str, String)>> {
    let output = git_command(workspace)
        .env_remove("GIT_CONFIG_NOSYSTEM")
        .env_remove("GIT_CONFIG_GLOBAL")
        .args([
            "config",
            "-z",
            "--get-regexp",
            r"^core\.(autocrlf|eol|filemode|ignorecase|symlinks)$",
        ])
        .output()?;
    if output.status.code() == Some(1) {
        return Ok(Vec::new());
    }
    if !output.status.success() {
        bail!("Git worktree configuration is unavailable");
    }
    let mut values = std::collections::BTreeMap::new();
    for entry in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = std::str::from_utf8(entry)?;
        let (name, value) = entry.split_once('\n').unwrap_or((entry, ""));
        let name = match name {
            "core.autocrlf" => "core.autocrlf",
            "core.eol" => "core.eol",
            "core.filemode" => "core.filemode",
            "core.ignorecase" => "core.ignorecase",
            "core.symlinks" => "core.symlinks",
            _ => bail!("Git worktree configuration is invalid"),
        };
        let value = value.trim().to_ascii_lowercase();
        let value = if value.is_empty() {
            "true".to_owned()
        } else {
            value
        };
        let allowed = match name {
            "core.autocrlf" => ["true", "false", "yes", "no", "on", "off", "1", "0", "input"]
                .contains(&value.as_str()),
            "core.eol" => ["lf", "crlf", "native"].contains(&value.as_str()),
            _ => ["true", "false", "yes", "no", "on", "off", "1", "0"].contains(&value.as_str()),
        };
        if !allowed {
            bail!("Git worktree configuration is invalid");
        }
        values.insert(name, value);
    }
    Ok(values.into_iter().collect())
}

fn git_status(workspace: &Path, repository: &Path, commit: &str) -> Result<Vec<u8>> {
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid Git commit");
    }
    let index = crate::read_limited(&git_path(workspace, "index")?, 64 * 1024 * 1024)?;
    let objects = git_path(workspace, "objects")?;
    let shadow = tempfile::tempdir()?;
    fs::create_dir(shadow.path().join("refs"))?;
    fs::create_dir(shadow.path().join("objects"))?;
    fs::create_dir(shadow.path().join("info"))?;
    let object_format = if commit.len() == 64 {
        "[extensions]\nobjectFormat = sha256\n"
    } else {
        ""
    };
    fs::write(shadow.path().join("HEAD"), format!("{commit}\n"))?;
    fs::write(
        shadow.path().join("config"),
        format!(
            "[core]\nrepositoryformatversion = {}\nbare = false\n{object_format}",
            usize::from(commit.len() == 64)
        ),
    )?;
    fs::write(shadow.path().join("index"), index)?;
    let exclude = git_path(workspace, "info/exclude")?;
    if exclude.exists() {
        fs::write(
            shadow.path().join("info/exclude"),
            crate::read_limited(&exclude, 1024 * 1024)?,
        )?;
    }
    let worktree_config = git_worktree_config(workspace)?;
    let shadow_command = || {
        let mut command = git_command(workspace);
        for (name, value) in &worktree_config {
            command.args(["-c", &format!("{name}={value}")]);
        }
        command
            .arg("--git-dir")
            .arg(shadow.path())
            .arg("--work-tree")
            .arg(repository)
            .env("GIT_OBJECT_DIRECTORY", &objects);
        command
    };
    let paths = shadow_command()
        .args([
            "ls-files",
            "--full-name",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            ".",
        ])
        .output()?;
    if !paths.status.success() {
        bail!(
            "Git working-tree paths are unavailable: {}",
            String::from_utf8_lossy(&paths.stderr).trim()
        );
    }
    let mut excluded = Vec::new();
    for path in paths
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let value = std::str::from_utf8(path)?;
        if private_path(value)? {
            excluded.push(format!(":(top,exclude,literal){value}"));
            if excluded.len() > MAX_CHANGED_FILES {
                bail!("too many excluded paths");
            }
        }
    }
    let output = shadow_command()
        .args([
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
            "--",
            ".",
        ])
        .args(&excluded)
        .output()?;
    if !output.status.success() {
        bail!(
            "Git working-tree status is unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn worktree_digest(workspace: &Path, repository: &Path, status: &[u8]) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(status);
    let mut entries = status.split(|byte| *byte == 0);
    let mut count = 0usize;
    let mut total = 0u64;
    while let Some(entry) = entries.next() {
        if entry.is_empty() {
            continue;
        }
        if entry.len() < 4 || entry[2] != b' ' {
            bail!("invalid Git status entry");
        }
        count += 1;
        if count > MAX_CHANGED_FILES {
            bail!("too many changed files");
        }
        let path = checked_relative(std::str::from_utf8(&entry[3..])?)?;
        if entry[0] == b'R' || entry[1] == b'R' || entry[0] == b'C' || entry[1] == b'C' {
            let original = entries
                .next()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| anyhow::anyhow!("invalid Git rename entry"))?;
            checked_relative(std::str::from_utf8(original)?)?;
        }
        let full = repository.join(path);
        let within = full.strip_prefix(workspace)?;
        let relative_workspace = within
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path encoding"))?;
        match std::fs::symlink_metadata(&full) {
            Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => {
                if metadata.len() > MAX_CHANGED_FILE_BYTES {
                    bail!("changed file exceeds size limit");
                }
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| anyhow::anyhow!("changed files exceed size limit"))?;
                if total > MAX_CHANGED_BYTES {
                    bail!("changed files exceed size limit");
                }
                let root = workspace
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid workspace encoding"))?;
                let mut file = crate::discovery::open_file(root, relative_workspace)?;
                let before = file.metadata()?;
                if !before.is_file() || before.len() != metadata.len() {
                    bail!("changed file is not stable");
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    hash.update(before.permissions().mode().to_le_bytes());
                }
                #[cfg(not(unix))]
                hash.update([u8::from(before.permissions().readonly())]);
                let mut file_hash = Sha256::new();
                let mut buffer = [0u8; 8192];
                let mut read = 0u64;
                loop {
                    let size = file.read(&mut buffer)?;
                    if size == 0 {
                        break;
                    }
                    read += size as u64;
                    if read > before.len() || read > MAX_CHANGED_FILE_BYTES {
                        bail!("changed file is not stable");
                    }
                    file_hash.update(&buffer[..size]);
                }
                let after = file.metadata()?;
                if read != before.len()
                    || after.len() != before.len()
                    || after.modified()? != before.modified()?
                    || after.permissions() != before.permissions()
                {
                    bail!("changed file is not stable");
                }
                hash.update(file_hash.finalize());
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && (entry[0] == b'D' || entry[1] == b'D') => {}
            _ => bail!("changed file cannot be inspected"),
        }
    }
    Ok(hex::encode(hash.finalize()))
}

pub fn capture_path(path: &Path) -> WorkspaceRevision {
    let workspace = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut revision = WorkspaceRevision {
        workspace: workspace.to_string_lossy().into_owned(),
        state: RepositoryState::Unavailable,
        repository: None,
        branch: None,
        commit: None,
        dirty: None,
        worktree_status_sha256: None,
        observed_at: crate::now(),
    };
    if !workspace.is_dir() {
        return revision;
    }
    let Ok(root) = git(&workspace, &["rev-parse", "--show-toplevel"]) else {
        return revision;
    };
    let Some(repository) = text(&root) else {
        if String::from_utf8_lossy(&root.stderr).contains("not a git repository") {
            revision.state = RepositoryState::NotGit;
        }
        return revision;
    };
    revision.state = RepositoryState::Git;
    revision.repository = Some(repository.clone());
    match git(&workspace, &["symbolic-ref", "--quiet", "--short", "HEAD"]) {
        Ok(output) if output.status.success() => revision.branch = text(&output),
        Ok(output) if output.status.code() == Some(1) => {}
        _ => {
            revision.state = RepositoryState::Unavailable;
            return revision;
        }
    }
    revision.commit = git(&workspace, &["rev-parse", "--verify", "HEAD^{commit}"])
        .ok()
        .and_then(|out| text(&out));
    if let Some(commit) = revision.commit.as_deref()
        && let Ok(status) = git_status(&workspace, Path::new(&repository), commit)
    {
        revision.dirty = Some(!status.is_empty());
        revision.worktree_status_sha256 = std::fs::canonicalize(&repository)
            .ok()
            .and_then(|root| worktree_digest(&workspace, &root, &status).ok());
    }
    revision
}

pub fn capture(profile: &Profile, profile_path: &Path) -> Vec<WorkspaceRevision> {
    let base = profile_path.parent().unwrap_or(Path::new("."));
    profile
        .workspaces
        .iter()
        .map(|path| capture_path(&base.join(path)))
        .collect()
}

pub fn configured_paths_match(
    revisions: &[WorkspaceRevision],
    profile: &Profile,
    profile_path: &Path,
) -> bool {
    let base = profile_path.parent().unwrap_or(Path::new("."));
    let current: Vec<_> = profile
        .workspaces
        .iter()
        .map(|path| {
            let path = base.join(path);
            path.canonicalize()
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let reviewed: Vec<_> = revisions
        .iter()
        .map(|revision| revision.workspace.clone())
        .collect();
    current == reviewed
}

pub fn fingerprint(revisions: &[WorkspaceRevision]) -> Option<String> {
    if revisions
        .iter()
        .all(|revision| revision.state == RepositoryState::NotGit)
    {
        return None;
    }
    let identities: Vec<_> = revisions.iter().map(WorkspaceRevision::identity).collect();
    Some(crate::digest(
        &serde_json::to_vec(&identities).expect("workspace revisions serialize"),
    ))
}

pub fn same_revisions(left: &[WorkspaceRevision], right: &[WorkspaceRevision]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.identity() == b.identity())
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct WorkspaceComparison {
    pub reviewed: WorkspaceRevision,
    pub current: WorkspaceRevision,
    /// The recorded Git identity and available changed-file fingerprint match.
    pub matches: bool,
}

pub fn compare(revisions: &[WorkspaceRevision]) -> Vec<WorkspaceComparison> {
    revisions
        .iter()
        .map(|reviewed| {
            let current = capture_path(Path::new(&reviewed.workspace));
            let matches = reviewed.identity() == current.identity()
                && current.state != RepositoryState::Unavailable
                && (current.state != RepositoryState::Git
                    || (current.commit.is_some()
                        && current.dirty.is_some()
                        && current.worktree_status_sha256.is_some()));
            WorkspaceComparison {
                reviewed: reviewed.clone(),
                current,
                matches,
            }
        })
        .collect()
}

pub fn unchanged_during_scan(revisions: &[WorkspaceRevision]) -> bool {
    revisions.iter().all(|reviewed| {
        capture_path(Path::new(&reviewed.workspace)).identity() == reviewed.identity()
    })
}

pub fn ensure_current(revisions: &[WorkspaceRevision]) -> Result<()> {
    if compare(revisions).iter().any(|item| {
        !item.matches
            || item.current.state == RepositoryState::Unavailable
            || item.current.state == RepositoryState::Git
                && (item.current.commit.is_none() || item.current.dirty.is_none())
    }) {
        bail!(
            "workspace Git context changed or is unavailable; rescan before recording review results"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reads_a_fresh_repository() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(dir.path())
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args(["-c", "commit.gpgsign=false"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        run(&["init"]);
        fs::write(dir.path().join("sample.txt"), "test").unwrap();
        run(&["add", "."]);
        run(&["commit", "-m", "fixture"]);
        let commit = run(&["rev-parse", "HEAD"]);
        assert!(
            git_status(dir.path(), dir.path(), &commit)
                .unwrap()
                .is_empty()
        );
    }
}
