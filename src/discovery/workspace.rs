use super::contracts::{FileReview, FileSlice};
use crate::{
    model::{EvidenceKind, Instance, Origin},
    profile::Profile,
    store::Store,
};
use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

const ENTRY_PAGE: usize = 256;
const SLICE_BYTES: u64 = 64 * 1024;
const DIRECTORIES_PER_PLAN: usize = 64;
/// Bump when exclusion or classification rules change: walked directories are listed again so
/// existing entries are reclassified, while unchanged reviewed files keep their review.
const CLASSIFICATION_RULES: &str = "3";
const GITIGNORE_BYTES: u64 = 1024 * 1024;
const DEPENDENCY_OUTPUT: [&str; 13] = [
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".gradle",
    ".terraform",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".sqlx",
];
const BUILD_MANIFESTS: [&str; 4] = ["Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts"];
const NATIVE_INVENTORY: &str =
    "parsed by the native lockfile/SBOM inventory; parse failures appear as inventory coverage";
const CANNOT_DECLARE: &str = "source or documentation file type cannot declare dependency versions";
const MEDIA: &str = "image, font or document binary cannot declare dependencies";
const ARTIFACT: &str =
    "binary artifact requires a separate artifact assessment (SBOM or explicit component)";
const NO_INLINE_METADATA: &str = "script source without inline dependency metadata (PEP 723 block, URL, npm: or jsr: imports, bundler/inline)";
const INLINE_PROBE_BYTES: u64 = 1024 * 1024;
/// Script extensions and the text through which such a file can declare dependencies.
const INLINE_MARKERS: [(&[&str], &[&str]); 3] = [
    (&["py", "pyw"], &["# /// script"]),
    (
        &["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"],
        &[
            "from \"http",
            "from 'http",
            "import(\"http",
            "import('http",
            "\"npm:",
            "'npm:",
            "\"jsr:",
            "'jsr:",
        ],
    ),
    (&["rb"], &["bundler/inline"]),
];
const REPOSITORY_METADATA: [&str; 4] =
    [".gitattributes", ".editorconfig", ".mailmap", "CODEOWNERS"];
const GIT_IGNORED: &str = "git-ignored path (generated or local output, not tracked source)";
const OUTPUT_DIRECTORY: &str = "dependency or build output directory (installed or generated)";

/// Returns the state and reason for files that need no agent review, or `None` to review.
fn file_classification(parent: &str, name: &str) -> Option<(&'static str, &'static str)> {
    if crate::inventory::native_inventory_file(name) {
        return Some(("excluded", NATIVE_INVENTORY));
    }
    let legal = ["LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS"]
        .iter()
        .any(|prefix| name.to_ascii_uppercase().starts_with(prefix));
    let ignore_patterns = name.starts_with('.') && name.ends_with("ignore");
    let service_registration = Path::new(parent).ends_with("META-INF/services");
    if legal || ignore_patterns || service_registration || REPOSITORY_METADATA.contains(&name) {
        return Some(("excluded", CANNOT_DECLARE));
    }
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "rs" | "java" | "go" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "swift" | "kt"
        | "scala" | "md" | "mdc" | "rst" | "adoc" | "bru" | "sql" => {
            Some(("excluded", CANNOT_DECLARE))
        }
        "png" | "jpg" | "jpeg" | "gif" | "ico" | "webp" | "bmp" | "svg" | "woff" | "woff2"
        | "ttf" | "otf" | "eot" | "pdf" => Some(("excluded", MEDIA)),
        "jar" | "war" | "ear" | "zip" | "whl" | "egg" | "so" | "dll" | "dylib" | "exe" | "tar"
        | "gz" | "tgz" | "class" => Some(("unavailable", ARTIFACT)),
        _ => None,
    }
}

fn inline_markers(name: &str) -> Option<&'static [&'static str]> {
    let (_, extension) = name.rsplit_once('.')?;
    let extension = extension.to_ascii_lowercase();
    INLINE_MARKERS
        .iter()
        .find(|(extensions, _)| extensions.contains(&extension.as_str()))
        .map(|(_, markers)| *markers)
}

/// Unreadable or oversized files count as declaring, so they stay in the review queue.
fn declares_inline(root: &str, relative: &str, markers: &[&str]) -> bool {
    let Ok(file) = open_file(root, relative) else {
        return true;
    };
    let mut bytes = Vec::new();
    if file
        .take(INLINE_PROBE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > INLINE_PROBE_BYTES
    {
        return true;
    }
    let text = String::from_utf8_lossy(&bytes);
    markers.iter().any(|marker| text.contains(marker))
}

/// `.gitignore` rules from the workspace root down to `relative`, outermost first.
/// Unreadable rule files are skipped, which only widens the reviewed set.
fn ignore_rules(root: &str, relative: &str) -> Vec<ignore::gitignore::Gitignore> {
    let mut rules = Vec::new();
    let mut directory = PathBuf::new();
    let levels = std::iter::once(None).chain(Path::new(relative).components().map(Some));
    for level in levels {
        if let Some(component) = level {
            directory.push(component);
        }
        let Some(file) = directory.join(".gitignore").to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(handle) = open_file(root, &file) else {
            continue;
        };
        let mut text = String::new();
        if handle
            .take(GITIGNORE_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            continue;
        }
        let mut builder =
            ignore::gitignore::GitignoreBuilder::new(Path::new(root).join(&directory));
        for line in text.lines() {
            // Git also skips malformed patterns.
            let _ = builder.add_line(None, line);
        }
        if let Ok(built) = builder.build() {
            rules.push(built);
        }
    }
    rules
}

fn git_ignored(rules: &[ignore::gitignore::Gitignore], path: &Path, is_dir: bool) -> bool {
    rules
        .iter()
        .rev()
        .find_map(|rule| match rule.matched(path, is_dir) {
            ignore::Match::None => None,
            ignore::Match::Ignore(_) => Some(true),
            ignore::Match::Whitelist(_) => Some(false),
        })
        .unwrap_or(false)
}

fn output_directory(parent: &Path, name: &str) -> bool {
    DEPENDENCY_OUTPUT.contains(&name)
        || (name == "target"
            && BUILD_MANIFESTS
                .iter()
                .any(|manifest| fs::symlink_metadata(parent.join(manifest)).is_ok()))
}

fn exclude_subtree(
    store: &Store,
    scope: &str,
    root: &str,
    child: &str,
    reason: &str,
) -> Result<()> {
    // A literal, case-sensitive prefix: LIKE would treat `_` and `%` in names as wildcards.
    let prefix = format!("{child}/");
    store.connection.execute(
        "DELETE FROM discovery_packages WHERE file_id IN (SELECT id FROM discovery_files WHERE scope=?1 AND root=?2 AND substr(path,1,length(?3))=?3)",
        params![scope, root, prefix],
    )?;
    store.connection.execute(
        "UPDATE discovery_files SET state='excluded',reason=?4 WHERE scope=?1 AND root=?2 AND substr(path,1,length(?3))=?3",
        params![scope, root, prefix, reason],
    )?;
    store.connection.execute(
        "UPDATE discovery_walk SET state='excluded',stamp=?4 WHERE scope=?1 AND root=?2 AND substr(path,1,length(?3))=?3",
        params![scope, root, prefix, reason],
    )?;
    Ok(())
}

/// 1-based file line where `excerpt` starts inside `chunk`.
fn excerpt_line(root: &str, relative: &str, chunk: &FileSlice, excerpt: &str) -> Option<usize> {
    let position = chunk.content.find(excerpt)?;
    let mut before = 0;
    if chunk.offset > 0 {
        let mut prefix = Vec::new();
        open_file(root, relative)
            .ok()?
            .take(chunk.offset)
            .read_to_end(&mut prefix)
            .ok()?;
        before = prefix.iter().filter(|byte| **byte == b'\n').count();
    }
    Some(before + chunk.content[..position].matches('\n').count() + 1)
}

/// Names inside `${name}` placeholders.
fn placeholders(text: &str) -> impl Iterator<Item = &str> {
    text.split("${")
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name))
}

pub(super) fn reopen(store: &Store, scope: &str, relative: &str) -> Result<usize> {
    let ids: Vec<String> = store
        .connection
        .prepare("SELECT id FROM discovery_files WHERE scope=?1 AND path=?2 AND state IN ('done','unavailable')")?
        .query_map(params![scope, relative], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if ids.is_empty() {
        bail!("no reviewed or unavailable discovery file at that workspace-relative path");
    }
    for id in &ids {
        store
            .connection
            .execute("DELETE FROM discovery_packages WHERE file_id=?1", [id])?;
        store.connection.execute(
            "UPDATE discovery_files SET state='pending',offset=0,reason='' WHERE id=?1",
            [id],
        )?;
    }
    Ok(ids.len())
}

fn stamp(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(format!(
        "{}:{:?}:{}",
        metadata.len(),
        metadata.modified()?,
        metadata.is_symlink()
    ))
}

fn missing(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

pub(crate) fn private_name(value: &str) -> bool {
    let name = value.to_ascii_lowercase();
    name == ".git"
        || name == ".env"
        || name.starts_with(".env.")
        || [
            ".ssh",
            ".aws",
            ".kube",
            ".gnupg",
            ".config",
            ".docker",
            ".azure",
            ".gcloud",
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            ".git-credentials",
            ".dockercfg",
            ".netrc",
            ".pypirc",
            "credentials",
            "credentials.json",
            "credentials.toml",
            "nuget.config",
            "auth.json",
            "id_rsa",
            "id_ed25519",
        ]
        .contains(&name.as_str())
        || [".pem", ".key", ".p12", ".pfx", ".tfvars", ".tfvars.json"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn checked_path(root: &str, relative: &str) -> Result<PathBuf> {
    let root = Path::new(root);
    if root.is_symlink() || root.canonicalize()? != root {
        bail!("workspace root changed or redirects");
    }
    let mut path = root.to_owned();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            bail!("discovery path must stay inside its workspace");
        };
        let name = name.to_str().context("discovery requires UTF-8 paths")?;
        if private_name(name) || name.chars().any(char::is_control) {
            bail!("private path is excluded from discovery");
        }
        path.push(name);
        if fs::symlink_metadata(&path)?.is_symlink() {
            bail!("discovery never follows symlinks");
        }
    }
    if path.canonicalize()? != path {
        bail!("discovery path changed");
    }
    Ok(path)
}

pub(super) fn prepare(
    profile: &Profile,
    profile_path: &Path,
    store: &Store,
    scope: &str,
) -> Result<()> {
    let base = profile_path.parent().unwrap_or(Path::new("."));
    for workspace in &profile.workspaces {
        let path = base.join(workspace);
        let root = path.canonicalize()?;
        if path.is_symlink() || !root.is_dir() || root.starts_with(crate::store::data_root()) {
            bail!("discovery workspace must be an authorized real project directory");
        }
        let root = root.to_str().context("workspace path must be UTF-8")?;
        adopt_reviews(store, scope, root)?;
        store.connection.execute(
            "INSERT OR IGNORE INTO discovery_walk VALUES (?1,?2,'','','','pending')",
            params![scope, root],
        )?;
    }
    let rules = format!("discovery_rules:{scope}");
    if store.meta(&rules)?.as_deref() != Some(CLASSIFICATION_RULES) {
        store.connection.execute(
            "UPDATE discovery_walk SET state='pending',cursor='' WHERE scope=?1 AND state='done'",
            [scope],
        )?;
        store.set_meta(&rules, CLASSIFICATION_RULES)?;
    }
    let mut query = store
        .connection
        .prepare("SELECT root,path,stamp FROM discovery_walk WHERE scope=?1 AND state IN ('done','unavailable')")?;
    let directories: Vec<(String, String, String)> = query
        .query_map([scope], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (root, relative, previous) in directories {
        let current = checked_path(&root, &relative).and_then(|path| stamp(&path));
        if !relative.is_empty() && current.as_ref().err().is_some_and(missing) {
            store.connection.execute("UPDATE discovery_walk SET state='removed',stamp='removed from workspace' WHERE scope=?1 AND root=?2 AND path=?3", params![scope,root,relative])?;
            continue;
        }
        if current.as_ref().ok() != Some(&previous) {
            store.connection.execute("UPDATE discovery_walk SET state='pending',cursor='' WHERE scope=?1 AND root=?2 AND path=?3", params![scope,root,relative])?;
        }
    }
    let mut query = store.connection.prepare(
        "SELECT id,root,path,stamp,state FROM discovery_files WHERE scope=?1 AND (state IN ('done','pending','unavailable') OR (state='excluded' AND reason=?2))",
    )?;
    let files: Vec<(String, String, String, String, String)> = query
        .query_map(params![scope, NO_INLINE_METADATA], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (id, root, relative, previous, state) in files {
        let current = checked_path(&root, &relative).and_then(|path| stamp(&path));
        if current.as_ref().err().is_some_and(missing) {
            store.connection.execute("UPDATE discovery_files SET state='removed',reason='removed from workspace' WHERE id=?1", [&id])?;
            store
                .connection
                .execute("DELETE FROM discovery_packages WHERE file_id=?1", [&id])?;
            continue;
        }
        if current.as_ref().ok() != Some(&previous) {
            let name = Path::new(&relative)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            let markers = inline_markers(name);
            if state == "excluded"
                && markers.is_some_and(|markers| !declares_inline(&root, &relative, markers))
            {
                store.connection.execute(
                    "UPDATE discovery_files SET stamp=?1 WHERE id=?2",
                    params![current.unwrap_or_default(), id],
                )?;
                continue;
            }
            store.connection.execute(
                "UPDATE discovery_files SET state='pending',offset=0,reason='',stamp=?1 WHERE id=?2",
                params![current.unwrap_or_default(), id],
            )?;
            store
                .connection
                .execute("DELETE FROM discovery_packages WHERE file_id=?1", [&id])?;
        }
    }
    for _ in 0..DIRECTORIES_PER_PLAN {
        if !expand(store, scope)? {
            break;
        }
    }
    Ok(())
}

/// Adding or removing a workspace changes the scope. A root without reviewed files in this scope
/// takes over the walk, file reviews and packages recorded for it under the earlier scope with the
/// most reviews; the stamp checks in `prepare` then reopen only what changed on disk.
fn adopt_reviews(store: &Store, scope: &str, root: &str) -> Result<()> {
    let reviewed: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM discovery_files WHERE scope=?1 AND root=?2 AND state='done')",
        params![scope, root],
        |row| row.get(0),
    )?;
    if reviewed {
        return Ok(());
    }
    let previous: Option<String> = store
        .connection
        .query_row(
            "SELECT scope FROM discovery_files WHERE root=?1 AND scope<>?2 AND state='done' GROUP BY scope ORDER BY COUNT(*) DESC, scope LIMIT 1",
            params![root, scope],
            |row| row.get(0),
        )
        .optional()?;
    let Some(previous) = previous else {
        return Ok(());
    };
    let transaction = store.connection.unchecked_transaction()?;
    transaction.execute(
        "DELETE FROM discovery_packages WHERE file_id IN (SELECT id FROM discovery_files WHERE scope=?1 AND root=?2)",
        params![scope, root],
    )?;
    transaction.execute(
        "DELETE FROM discovery_files WHERE scope=?1 AND root=?2",
        params![scope, root],
    )?;
    transaction.execute(
        "DELETE FROM discovery_walk WHERE scope=?1 AND root=?2",
        params![scope, root],
    )?;
    let files: Vec<(String, String)> = transaction
        .prepare("SELECT id,path FROM discovery_files WHERE scope=?1 AND root=?2")?
        .query_map(params![previous, root], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (old_id, relative) in files {
        let id = crate::digest(format!("{scope}:{root}:{relative}").as_bytes());
        transaction.execute(
            "UPDATE discovery_files SET id=?1,scope=?2 WHERE id=?3",
            params![id, scope, old_id],
        )?;
        transaction.execute(
            "UPDATE discovery_packages SET file_id=?1,scope=?2 WHERE file_id=?3",
            params![id, scope, old_id],
        )?;
    }
    transaction.execute(
        "UPDATE discovery_walk SET scope=?1 WHERE scope=?2 AND root=?3",
        params![scope, previous, root],
    )?;
    transaction.execute(
        "DELETE FROM meta WHERE key=?1",
        [format!("discovery_rules:{scope}")],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO discovery_sources SELECT ?1,instance_id,fingerprint,checked_at,body FROM discovery_sources WHERE scope=?2",
        params![scope, previous],
    )?;
    transaction.commit()?;
    Ok(())
}

/// Expands one pending directory page; returns false when none is pending.
fn expand(store: &Store, scope: &str) -> Result<bool> {
    let directory: Option<(String,String,String,String)> = store.connection.query_row(
        "SELECT root,path,cursor,stamp FROM discovery_walk WHERE scope=?1 AND state='pending' ORDER BY root,path LIMIT 1", [scope],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
    let Some((root, relative, mut cursor, previous)) = directory else {
        return Ok(false);
    };
    let result = checked_path(&root,&relative).and_then(|path| {
        let current = stamp(&path)?;
        if current != previous { cursor.clear(); }
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(&path)? {
            let name = entry?.file_name().into_string().map_err(|_| anyhow::anyhow!("non-UTF-8 entry; directory coverage unavailable"))?;
            if name > cursor {
                names.insert(name);
                if names.len() > ENTRY_PAGE { names.pop_last(); }
            }
        }
        if stamp(&path)? != current { bail!("directory changed while enumerating; retry discovery"); }
        let rules = ignore_rules(&root, &relative);
        let count = names.len();
        for name in names {
            let child = if relative.is_empty() {
                name.clone()
            } else {
                format!("{relative}/{name}")
            };
            let child = child.as_str();
            let entry = path.join(&name);
            let metadata = fs::symlink_metadata(&entry)?;
            let private = private_name(&name) || name.chars().any(char::is_control) || metadata.is_symlink();
            let ignored = !private && git_ignored(&rules, &entry, metadata.is_dir());
            if metadata.is_dir() && !private {
                let skipped = if ignored {
                    Some(GIT_IGNORED)
                } else if output_directory(&path, &name) {
                    Some(OUTPUT_DIRECTORY)
                } else {
                    None
                };
                let (state, reason) = match skipped {
                    Some(reason) => ("excluded", reason),
                    None => ("pending", ""),
                };
                store.connection.execute("INSERT INTO discovery_walk VALUES (?1,?2,?3,'',?4,?5) ON CONFLICT(scope,root,path) DO UPDATE SET state=excluded.state,cursor='',stamp=excluded.stamp WHERE discovery_walk.state='removed' OR (discovery_walk.state='excluded')<>(excluded.state='excluded')", params![scope,root,child,reason,state])?;
                if let Some(reason) = skipped {
                    exclude_subtree(store, scope, &root, child, reason)?;
                }
            } else {
                let id = crate::digest(format!("{scope}:{root}:{child}").as_bytes());
                let (state, reason) = if private || !metadata.is_file() {
                    ("excluded", "private path, symlink, VCS metadata or nonregular file")
                } else if ignored {
                    ("excluded", GIT_IGNORED)
                } else if let Some(classified) = file_classification(&relative, &name) {
                    classified
                } else if inline_markers(&name)
                    .is_some_and(|markers| !declares_inline(&root, child, markers))
                {
                    ("excluded", NO_INLINE_METADATA)
                } else {
                    ("pending", "")
                };
                store.connection.execute("INSERT INTO discovery_files VALUES (?1,?2,?3,?4,?5,0,?6,?7) ON CONFLICT(id) DO UPDATE SET state=excluded.state,offset=0,stamp=excluded.stamp,reason=excluded.reason WHERE discovery_files.state='removed' OR (discovery_files.state<>excluded.state AND (discovery_files.state IN ('excluded','unavailable') OR excluded.state IN ('excluded','unavailable')))", params![id,scope,root,child,stamp(&entry)?,state,reason])?;
                if state != "pending" {
                    store.connection.execute("DELETE FROM discovery_packages WHERE file_id=?1", [&id])?;
                }
            }
            cursor = name;
        }
        store.connection.execute("UPDATE discovery_walk SET cursor=?1,stamp=?2,state=?3 WHERE scope=?4 AND root=?5 AND path=?6", params![cursor,current,if count < ENTRY_PAGE {"done"}else{"pending"},scope,root,relative])?;
        Ok(())
    });
    if let Err(error) = result {
        let state = if !relative.is_empty() && missing(&error) {
            "removed"
        } else {
            "unavailable"
        };
        store.connection.execute(
            "UPDATE discovery_walk SET state=?1,stamp=?2 WHERE scope=?3 AND root=?4 AND path=?5",
            params![state, error.to_string(), scope, root, relative],
        )?;
    }
    Ok(true)
}

pub(super) fn slice(store: &Store, scope: &str, id: &str) -> Result<FileSlice> {
    let (root, relative, offset): (String, String, u64) = store.connection.query_row(
        "SELECT root,path,offset FROM discovery_files WHERE scope=?1 AND id=?2 AND state='pending'",
        params![scope, id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    read_slice(&root, &relative, id, offset)
}

fn read_slice(root: &str, relative: &str, id: &str, offset: u64) -> Result<FileSlice> {
    let path = checked_path(root, relative)?;
    let before = stamp(&path)?;
    let mut file = open_file(root, relative)?;
    if !file.metadata()?.is_file() {
        bail!("discovery input must be a regular file");
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(SLICE_BYTES).read_to_end(&mut bytes)?;
    if bytes.contains(&0) {
        bail!("binary file excluded from text discovery");
    }
    let valid = match std::str::from_utf8(&bytes) {
        Ok(_) => bytes.len(),
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        Err(_) => bail!("non-UTF-8 file requires a separate artifact assessment"),
    };
    bytes.truncate(valid);
    let content = String::from_utf8(bytes)?;
    if content.contains("-----BEGIN ") && content.contains("PRIVATE KEY-----") {
        bail!("private key material excluded from discovery");
    }
    if stamp(&path)? != before {
        bail!("file changed during discovery");
    }
    Ok(FileSlice {
        file_id: id.to_owned(),
        path: relative.to_owned(),
        offset,
        end: offset + content.len() as u64,
        sha256: crate::digest(content.as_bytes()),
        content,
    })
}

#[cfg(unix)]
pub(crate) fn open_file(root: &str, relative: &str) -> Result<fs::File> {
    use nix::{
        fcntl::{OFlag, open, openat},
        sys::stat::Mode,
    };
    let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    let mut directory = open(Path::new(root), flags | OFlag::O_DIRECTORY, Mode::empty())?;
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            bail!("invalid workspace path component");
        };
        let final_component = components.peek().is_none();
        let child_flags = if final_component {
            flags
        } else {
            flags | OFlag::O_DIRECTORY
        };
        let descriptor = openat(&directory, Path::new(name), child_flags, Mode::empty())?;
        if final_component {
            return Ok(fs::File::from(descriptor));
        }
        directory = descriptor;
    }
    bail!("select a file below the workspace root")
}

#[cfg(not(unix))]
pub(crate) fn open_file(root: &str, relative: &str) -> Result<fs::File> {
    Ok(fs::File::open(checked_path(root, relative)?)?)
}

pub(super) fn page(store: &Store, scope: &str, limit: usize) -> Result<Vec<FileSlice>> {
    let mut query = store.connection.prepare("SELECT id FROM discovery_files WHERE scope=?1 AND state='pending' ORDER BY root,path LIMIT ?2")?;
    let ids: Vec<String> = query
        .query_map(params![scope, limit], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut slices = Vec::new();
    for id in ids {
        match slice(store, scope, &id) {
            Ok(chunk) => slices.push(chunk),
            Err(error) => {
                store.connection.execute(
                    "UPDATE discovery_files SET state='unavailable',reason=?1 WHERE id=?2",
                    params![error.to_string(), id],
                )?;
            }
        }
    }
    Ok(slices)
}

pub(super) fn import(
    profile: &Profile,
    store: &mut Store,
    scope: &str,
    reviews: Vec<FileReview>,
) -> Result<()> {
    let mut prepared = Vec::new();
    let mut seen = BTreeSet::new();
    for review in reviews {
        if !seen.insert(review.file_id.clone())
            || review.packages.len() > 1000
            || review.rationale.trim().is_empty()
            || review.rationale.len() > 4000
        {
            bail!("duplicate file review, excessive packages or missing bounded rationale");
        }
        let chunk = slice(store, scope, &review.file_id)?;
        if review.offset != chunk.offset || review.sha256 != chunk.sha256 {
            bail!("stale discovery chunk; reread current page");
        }
        let (root, relative): (String, String) = store.connection.query_row(
            "SELECT root,path FROM discovery_files WHERE id=?1",
            [&review.file_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut packages = Vec::new();
        for observation in &review.packages {
            if observation.direct.is_some() {
                let name = std::path::Path::new(&relative)
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("");
                if ![
                    "pom.xml",
                    "Cargo.toml",
                    "package.json",
                    "composer.json",
                    "pyproject.toml",
                    "go.mod",
                ]
                .contains(&name)
                    || !observation
                        .direct_rationale
                        .as_ref()
                        .is_some_and(|r| !r.trim().is_empty() && r.len() <= 2000)
                {
                    bail!(
                        "directness requires a supported manifest excerpt and a bounded rationale"
                    );
                }
            } else if observation.direct_rationale.is_some() {
                bail!("directness rationale requires an explicit relationship");
            }
            let mut candidate = profile.clone();
            candidate.components = vec![observation.component.clone()];
            if !crate::profile::validate(&candidate).valid
                || observation.component.usage != crate::profile::Usage::Tracked
                || observation.component.upstream.is_some()
                || !observation.component.feeds.is_empty()
            {
                bail!(
                    "workspace observations cannot grant deployment, upstream identity or feed access"
                );
            }
            if observation.excerpt.trim().is_empty()
                || observation.excerpt.len() > 8000
                || !chunk.content.contains(&observation.excerpt)
            {
                bail!("package excerpt must match the current file chunk");
            }
            let component = &observation.component;
            let version_source = match &observation.version_excerpt {
                None => observation.excerpt.as_str(),
                Some(definition) => {
                    let defined = placeholders(&observation.excerpt)
                        .any(|name| !name.is_empty() && definition.contains(name));
                    if definition.trim().is_empty()
                        || definition.len() > 2000
                        || !chunk.content.contains(definition.as_str())
                        || component.version.is_none()
                        || !defined
                    {
                        bail!(
                            "version_excerpt must come from the same chunk and define a ${{name}} placeholder used by the package excerpt"
                        );
                    }
                    definition.as_str()
                }
            };
            if let Some(version) = &component.version
                && (version == "latest"
                    || version.contains(['*', '^', '~', '>', '<', '=', '|'])
                    || !version_source.contains(version)
                    || ["^", "~", ">=", "<=", "!="].iter().any(|operator| {
                        version_source.contains(&format!("{operator}{version}"))
                            || version_source.contains(&format!("{operator} {version}"))
                    }))
            {
                bail!("workspace discovery requires a literal exact version or unknown");
            }
            let name = if component.reference.starts_with("pkg:") {
                let purl: packageurl::PackageUrl<'_> = component.reference.parse()?;
                purl.name().to_owned()
            } else {
                component.reference.clone()
            };
            if !observation
                .excerpt
                .to_lowercase()
                .contains(&name.to_lowercase())
            {
                bail!("package name is absent from its cited source excerpt");
            }
            let mut instance = Instance::declared(component);
            instance.id = crate::digest(
                format!(
                    "{}:{}:{}:{:?}",
                    review.file_id, component.reference, root, component.version
                )
                .as_bytes(),
            );
            instance.origin = Origin::AgentObserved;
            instance.provenance.path = Some(relative.clone());
            instance.provenance.workspace = Some(root.clone());
            instance.provenance.sha256 = chunk.sha256.clone();
            instance.provenance.direct = observation.direct;
            instance.provenance.line = excerpt_line(&root, &relative, &chunk, &observation.excerpt);
            instance.identity_evidence.push(store.record_evidence(
                &serde_json::to_vec(observation)?,
                "agent_workspace_observation",
                None,
                EvidenceKind::Context,
            )?);
            packages.push(instance);
        }
        let path = checked_path(&root, &relative)?;
        let finished = chunk.end == fs::metadata(&path)?.len()
            && review.coverage == crate::research::ReviewCoverage::Complete;
        if review.coverage != crate::research::ReviewCoverage::Complete {
            bail!(
                "file review is incomplete; current chunk remains pending: {}",
                review.rationale
            );
        }
        let body = serde_json::to_string(&review)?;
        prepared.push((
            review.file_id,
            chunk,
            packages,
            finished,
            stamp(&path)?,
            body,
        ));
    }
    let transaction = store.connection.transaction()?;
    for (id, chunk, packages, finished, current_stamp, body) in prepared {
        transaction.execute("INSERT INTO discovery_history(scope,phase,body,recorded_at) VALUES (?1,'workspace',?2,?3)",params![scope,body,crate::now()])?;
        for instance in packages {
            transaction.execute(
                "INSERT OR REPLACE INTO discovery_packages VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    instance.id,
                    scope,
                    id,
                    chunk.offset,
                    chunk.end,
                    chunk.sha256,
                    serde_json::to_string(&instance)?
                ],
            )?;
        }
        transaction.execute(
            "UPDATE discovery_files SET offset=?1,state=?2,stamp=?3,reason='' WHERE id=?4",
            params![
                chunk.end,
                if finished { "done" } else { "pending" },
                current_stamp,
                id
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

/// Workspace-relative files that discovery reviewed or excluded with a recorded reason.
pub(super) fn settled_paths(
    store: &Store,
    scope: &str,
) -> Result<std::collections::HashSet<String>> {
    let mut query = store.connection.prepare(
        "SELECT path FROM discovery_files WHERE scope=?1 AND state IN ('done','excluded')",
    )?;
    let paths = query
        .query_map([scope], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(paths)
}

pub(super) fn instances(store: &Store, scope: &str) -> Result<Vec<Instance>> {
    let mut query = store.connection.prepare("SELECT p.body,f.root,f.path,p.start,p.sha256 FROM discovery_packages p JOIN discovery_files f ON p.file_id=f.id WHERE p.scope=?1")?;
    let rows: Vec<(String, String, String, u64, String)> = query
        .query_map([scope], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut instances = Vec::new();
    let mut validated = std::collections::HashMap::new();
    for (body, root, path, start, hash) in rows {
        let key = (root.clone(), path.clone(), start, hash.clone());
        let valid = *validated.entry(key).or_insert_with(|| {
            read_slice(&root, &path, "", start).is_ok_and(|chunk| chunk.sha256 == hash)
        });
        if valid {
            instances.push(serde_json::from_str(&body)?);
        }
    }
    Ok(instances)
}
