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

fn private_name(value: &str) -> bool {
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
        || [".pem", ".key", ".p12", ".pfx"]
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
        store.connection.execute(
            "INSERT OR IGNORE INTO discovery_walk VALUES (?1,?2,'','','','pending')",
            params![scope, root],
        )?;
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
        "SELECT id,root,path,stamp FROM discovery_files WHERE scope=?1 AND state IN ('done','pending','unavailable')",
    )?;
    let files: Vec<(String, String, String, String)> = query
        .query_map([scope], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (id, root, relative, previous) in files {
        let current = checked_path(&root, &relative).and_then(|path| stamp(&path));
        if current.as_ref().err().is_some_and(missing) {
            store.connection.execute("UPDATE discovery_files SET state='removed',reason='removed from workspace' WHERE id=?1", [&id])?;
            store
                .connection
                .execute("DELETE FROM discovery_packages WHERE file_id=?1", [&id])?;
            continue;
        }
        if current.as_ref().ok() != Some(&previous) {
            store.connection.execute(
                "UPDATE discovery_files SET state='pending',offset=0,stamp=?1 WHERE id=?2",
                params![current.unwrap_or_default(), id],
            )?;
            store
                .connection
                .execute("DELETE FROM discovery_packages WHERE file_id=?1", [&id])?;
        }
    }
    expand(store, scope)
}

fn expand(store: &Store, scope: &str) -> Result<()> {
    let directory: Option<(String,String,String,String)> = store.connection.query_row(
        "SELECT root,path,cursor,stamp FROM discovery_walk WHERE scope=?1 AND state='pending' ORDER BY root,path LIMIT 1", [scope],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
    let Some((root, relative, mut cursor, previous)) = directory else {
        return Ok(());
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
        let count = names.len();
        for name in names {
            let child = Path::new(&relative).join(&name);
            let child = child.to_str().context("invalid child path")?;
            let entry = path.join(&name);
            let metadata = fs::symlink_metadata(&entry)?;
            let excluded = private_name(&name) || name.chars().any(char::is_control) || metadata.is_symlink();
            if metadata.is_dir() && !excluded {
                store.connection.execute("INSERT INTO discovery_walk VALUES (?1,?2,?3,'','','pending') ON CONFLICT(scope,root,path) DO UPDATE SET state='pending',cursor='',stamp='' WHERE discovery_walk.state='removed'", params![scope,root,child])?;
            } else {
                let id = crate::digest(format!("{scope}:{root}:{child}").as_bytes());
                let state = if excluded || !metadata.is_file() { "excluded" } else { "pending" };
                let reason = if state == "excluded" { "private path, symlink, VCS metadata or nonregular file" } else { "" };
                store.connection.execute("INSERT INTO discovery_files VALUES (?1,?2,?3,?4,?5,0,?6,?7) ON CONFLICT(id) DO UPDATE SET state=excluded.state,offset=0,stamp=excluded.stamp,reason=excluded.reason WHERE discovery_files.state='removed'", params![id,scope,root,child,stamp(&entry)?,state,reason])?;
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
    Ok(())
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
fn open_file(root: &str, relative: &str) -> Result<fs::File> {
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
fn open_file(root: &str, relative: &str) -> Result<fs::File> {
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
            if let Some(version) = &component.version
                && (version == "latest"
                    || version.contains(['*', '^', '~', '>', '<', '=', '|'])
                    || !observation.excerpt.contains(version)
                    || ["^", "~", ">=", "<=", "!="].iter().any(|operator| {
                        observation
                            .excerpt
                            .contains(&format!("{operator}{version}"))
                            || observation
                                .excerpt
                                .contains(&format!("{operator} {version}"))
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
            instance.provenance.direct = None;
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
