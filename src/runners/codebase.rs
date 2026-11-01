use crate::{discovery, inventory, profile, store::Store};
use anyhow::{Context, Result, bail};
use ignore::{DirEntry, WalkBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Read, Write},
    path::Path,
    sync::LazyLock,
    time::{Duration, Instant},
};

const FILE_LIMIT: u64 = 512 * 1024;
const MAX_FILES: usize = 20_000;
const SEARCH_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MESSAGE: usize = 1024 * 1024;
static CREDENTIAL_URL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s/"'<>]*@"#)
        .expect("static credential URL pattern")
});

fn private_manifest(name: &str) -> bool {
    discovery::requirements_file(name)
        || name.eq_ignore_ascii_case("composer.json")
        || inventory::native_inventory_file(name)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    codebase: usize,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    start_line: Option<usize>,
    #[serde(default)]
    line_count: Option<usize>,
}

fn visible_base(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !discovery::private_name(&name)
        && !name.chars().any(char::is_control)
        && !(entry.file_type().is_some_and(|kind| kind.is_dir())
            && (inventory::excluded_directory(&name) || entry.path().join(".git").exists()))
        && !entry.file_type().is_some_and(|kind| kind.is_symlink())
}

fn visible(entry: &DirEntry) -> bool {
    visible_base(entry)
        && (entry.depth() == 0 || !private_manifest(&entry.file_name().to_string_lossy()))
}

pub(crate) fn preflight(store: &Store) -> Result<()> {
    store.ensure_workspace_current()?;
    let started = Instant::now();
    let mut remaining = 1024 * 1024_u64;
    for revision in store.latest()?.workspace_revisions {
        let root = Path::new(&revision.workspace);
        let mut walk = WalkBuilder::new(root);
        walk.hidden(false)
            .follow_links(false)
            .require_git(false)
            .filter_entry(visible_base);
        let mut files = 0_usize;
        for entry in walk.build() {
            if started.elapsed() >= Duration::from_secs(15) {
                bail!("source privacy preflight exceeded its time limit");
            }
            let entry = entry.context("cannot complete source privacy preflight")?;
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            files += 1;
            if files > MAX_FILES {
                bail!("source privacy preflight exceeds its file limit");
            }
            if !discovery::requirements_file(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .context("requirements path is not UTF-8")?;
            let mut bytes = Vec::new();
            let mut file = discovery::open_file(&revision.workspace, relative)?;
            let before = file.metadata()?;
            std::io::Read::by_ref(&mut file)
                .take(remaining.saturating_add(1))
                .read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            if before.len() != after.len() || before.modified()? != after.modified()? {
                bail!("requirements changed during source privacy preflight");
            }
            if bytes.len() as u64 > remaining {
                bail!("source privacy preflight exceeds its input limit");
            }
            remaining -= bytes.len() as u64;
            let text = std::str::from_utf8(&bytes).context("requirements input is not UTF-8")?;
            if discovery::has_untrusted_sources(text) {
                bail!(
                    "automatic source review is unavailable because requirements include external or ambiguous sources; inspect the codebase manually"
                );
            }
        }
    }
    store.ensure_workspace_current()?;
    Ok(())
}

fn paths(root: &Path, prefix: Option<&str>) -> Result<(Vec<String>, bool)> {
    let prefix = prefix.map(Path::new);
    if let Some(prefix) = prefix {
        if prefix.as_os_str().is_empty()
            || prefix.components().any(|part| match part {
                std::path::Component::Normal(name) => {
                    inventory::excluded_directory(&name.to_string_lossy())
                }
                _ => true,
            })
        {
            bail!("invalid or excluded source prefix");
        }
        discovery::checked_path(
            root.to_str().context("codebase root is not UTF-8")?,
            prefix.to_str().context("prefix is not UTF-8")?,
        )?;
    }
    let root_path = root.to_owned();
    let prefix = prefix.map(Path::to_owned);
    let mut walk = WalkBuilder::new(root);
    walk.hidden(false)
        .follow_links(false)
        .require_git(false)
        .filter_entry(move |entry| {
            if !visible(entry) {
                return false;
            }
            let Some(prefix) = &prefix else {
                return true;
            };
            let Ok(relative) = entry.path().strip_prefix(&root_path) else {
                return false;
            };
            relative.as_os_str().is_empty()
                || relative.starts_with(prefix)
                || prefix.starts_with(relative)
        });
    let mut files = Vec::new();
    let mut complete = true;
    for entry in walk.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let relative = entry.path().strip_prefix(root)?;
        let Some(path) = relative.to_str() else {
            complete = false;
            continue;
        };
        files.push(crate::slash_path(Path::new(path)));
        if files.len() > MAX_FILES {
            complete = false;
            break;
        }
    }
    files.sort_unstable();
    files.truncate(MAX_FILES);
    Ok((files, complete))
}

fn file_text(root: &str, relative: &str) -> Result<String> {
    if Path::new(relative)
        .file_name()
        .is_some_and(|name| private_manifest(&name.to_string_lossy()))
    {
        bail!("dependency input may contain private identities or source credentials");
    }
    discovery::checked_path(root, relative)?;
    let file = discovery::open_file(root, relative)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > FILE_LIMIT {
        bail!("file is unavailable or exceeds the source read limit");
    }
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FILE_LIMIT || bytes.contains(&0) {
        bail!("file is not bounded text");
    }
    let content = String::from_utf8(bytes).context("file is not UTF-8 text")?;
    if content.contains("-----BEGIN ") && content.contains("PRIVATE KEY-----") {
        bail!("private key material is excluded");
    }
    if CREDENTIAL_URL.is_match(&content) {
        bail!("source with URL credentials is excluded");
    }
    Ok(content)
}

pub(crate) fn ensure_visible(store: &Store, codebase: usize, path: &str) -> Result<()> {
    store.ensure_workspace_current()?;
    let snapshot = store.latest()?;
    let root = &snapshot
        .workspace_revisions
        .get(codebase)
        .context("codebase is outside the monitor")?
        .workspace;
    let (files, complete) = paths(Path::new(root), Some(path))?;
    if !complete || !files.iter().any(|file| file == path) {
        bail!("citation refers to an excluded or unavailable source file");
    }
    file_text(root, path)?;
    Ok(())
}

fn execute(store: &Store, roots: &[String], name: &str, args: Arguments) -> Result<Value> {
    store.ensure_workspace_current()?;
    let volatile = store
        .latest()?
        .workspace_revisions
        .iter()
        .any(|revision| revision.state != crate::workspace_revision::RepositoryState::Git);
    if volatile {
        preflight(store)?;
    }
    let root = roots
        .get(args.codebase)
        .context("codebase index is outside the monitor")?;
    let (files, complete) = paths(Path::new(root), args.path.as_deref())?;
    let result = match name {
        "codebase_list" => {
            let offset = args.offset.unwrap_or(0);
            if offset > files.len() {
                bail!("offset is outside the file list");
            }
            let end = offset.saturating_add(50).min(files.len());
            json!({"paths":&files[offset..end],"next_offset":(end < files.len()).then_some(end),"complete":complete})
        }
        "codebase_read" => {
            let path = args.path.context("path is required")?;
            if !files.iter().any(|candidate| candidate == &path) {
                bail!("file is excluded or unavailable");
            }
            let text = file_text(root, &path)?;
            let start = args.start_line.unwrap_or(1);
            if start == 0 {
                bail!("start_line must be positive");
            }
            let line_count = args.line_count.unwrap_or(100);
            if !(1..=100).contains(&line_count) {
                bail!("line_count must be 1..100");
            }
            let lines: Vec<_> = text.lines().skip(start - 1).take(line_count).enumerate().map(|(offset, line)| {
                json!({"line":start+offset,"text":line,"sha256":crate::digest(line.as_bytes())})
            }).collect();
            if serde_json::to_vec(&lines)?.len() > 24 * 1024 {
                bail!("selected lines exceed the read limit");
            }
            let next = start.saturating_add(line_count);
            json!({"path":path,"lines":lines,"next_line":(text.lines().count() >= next).then_some(next)})
        }
        "codebase_search" => {
            let query = args.query.context("query is required")?;
            if query.is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
                bail!("query must be 1..256 printable bytes");
            }
            let mut matches = Vec::new();
            let mut inspected = 0;
            let mut exhausted = !complete;
            for path in &files {
                let text = match file_text(root, path) {
                    Ok(text) => text,
                    Err(_) => {
                        exhausted = true;
                        continue;
                    }
                };
                inspected += text.len() as u64;
                if inspected > SEARCH_BYTES {
                    exhausted = true;
                    break;
                }
                for (line, content) in text.lines().enumerate() {
                    if content.contains(&query) {
                        if content.len() > 1000 {
                            exhausted = true;
                            continue;
                        }
                        matches.push(json!({"path":path,"line":line+1,"text":content,"sha256":crate::digest(content.as_bytes())}));
                        if matches.len() == 20 {
                            exhausted = true;
                            break;
                        }
                    }
                }
                if matches.len() == 20 {
                    break;
                }
            }
            json!({"matches":matches,"complete":!exhausted})
        }
        _ => bail!("unknown source tool"),
    };
    if serde_json::to_vec(&result)?.len() > 24 * 1024 {
        bail!("result exceeds the bounded agent response; narrow the request");
    }
    if volatile {
        preflight(store)?;
    }
    store.ensure_workspace_current()?;
    Ok(result)
}

/// Serves read-only, bounded codebase tools for an agent reviewing the current monitor snapshot.
pub fn serve_codebase(project: &Path, receipt: Option<&Path>) -> Result<()> {
    let profile = profile::load(project)?;
    let store = Store::open(&profile.project_id.to_string())?;
    preflight(&store)?;
    if let Some(receipt) = receipt {
        let jobs = store.directory.join("jobs").canonicalize()?;
        let parent = receipt
            .parent()
            .context("receipt needs a parent directory")?
            .canonicalize()?;
        if !parent.starts_with(jobs) || receipt.file_name().is_none() {
            bail!("source access receipt must be in this monitor's job directory");
        }
    }
    let roots: Vec<String> = store
        .latest()?
        .workspace_revisions
        .into_iter()
        .map(|revision| revision.workspace)
        .collect();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let count = (&mut input)
            .take((MAX_MESSAGE + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        if count > MAX_MESSAGE {
            bail!("MCP request exceeds limit");
        }
        let message: Value = serde_json::from_slice(&line)?;
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => {
                json!({"protocolVersion":message.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2025-03-26"),"capabilities":{"tools":{}},"serverInfo":{"name":"vulnbell-codebase","version":env!("CARGO_PKG_VERSION")}})
            }
            Some("ping") => json!({}),
            Some("tools/list") => {
                let schema = json!({"type":"object","properties":{"codebase":{"type":"integer","minimum":0},"path":{"type":"string"},"query":{"type":"string"},"offset":{"type":"integer","minimum":0},"start_line":{"type":"integer","minimum":1},"line_count":{"type":"integer","minimum":1,"maximum":100}},"required":["codebase"],"additionalProperties":false});
                let tool = |name, description| json!({"name":name,"description":description,"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false},"inputSchema":schema});
                json!({"tools":[tool("codebase_list","List selected codebase files with a paginated offset; an optional path narrows the subtree. Excludes private, ignored, dependency and build output paths."),tool("codebase_read","Read up to 100 lines of a selected codebase file with one-based line numbers and hashes."),tool("codebase_search","Find a literal string in selected codebase files; an optional path narrows the subtree. complete=false means the search was bounded or skipped files.")]})
            }
            Some("tools/call") => {
                let outcome = (|| -> Result<Value> {
                    let name = message
                        .pointer("/params/name")
                        .and_then(Value::as_str)
                        .context("missing tool name")?;
                    let args = serde_json::from_value(
                        message
                            .pointer("/params/arguments")
                            .cloned()
                            .context("missing arguments")?,
                    )?;
                    let result = execute(&store, &roots, name, args)?;
                    if let Some(receipt) =
                        receipt.filter(|_| matches!(name, "codebase_read" | "codebase_search"))
                    {
                        crate::atomic_write(
                            receipt,
                            &serde_json::to_vec(
                                &json!({"schema_version":1,"project_id":profile.project_id.to_string(),"source_read":true}),
                            )?,
                        )?;
                    }
                    Ok(result)
                })();
                match outcome {
                    Ok(value) => json!({"content":[{"type":"text","text":value.to_string()}]}),
                    Err(error) => {
                        json!({"isError":true,"content":[{"type":"text","text":error.to_string()}]})
                    }
                }
            }
            _ => {
                writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}})
                )?;
                stdout.flush()?;
                continue;
            }
        };
        writeln!(
            stdout,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"result":result})
        )?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{file_text, paths};
    use std::fs;

    #[test]
    fn source_inventory_skips_private_ignored_and_dependency_trees() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(".gitignore"), "ignored.rs\n").unwrap();
        fs::write(directory.path().join("source.rs"), "fn visible() {}\n").unwrap();
        fs::write(directory.path().join("ignored.rs"), "ignored\n").unwrap();
        fs::write(directory.path().join(".env"), "secret\n").unwrap();
        fs::write(
            directory.path().join("requirements-dev.txt"),
            "private @ https://user:secret@example.invalid/pkg.whl\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("composer.json"),
            "{\"repositories\": []}\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("Cargo.lock"),
            "# synthetic lockfile\n",
        )
        .unwrap();
        fs::create_dir(directory.path().join("node_modules")).unwrap();
        fs::write(
            directory.path().join("node_modules/package.js"),
            "dependency\n",
        )
        .unwrap();
        fs::create_dir(directory.path().join("target")).unwrap();
        fs::write(directory.path().join("target/generated.rs"), "generated\n").unwrap();
        fs::create_dir_all(directory.path().join("nested/.git")).unwrap();
        fs::write(directory.path().join("nested/source.rs"), "submodule\n").unwrap();
        let (files, complete) = paths(directory.path(), None).unwrap();
        assert!(complete);
        assert!(files.iter().any(|path| path == "source.rs"));
        for forbidden in [
            ".env",
            "requirements-dev.txt",
            "composer.json",
            "Cargo.lock",
            "ignored.rs",
            "node_modules/package.js",
            "target/generated.rs",
            "nested/source.rs",
        ] {
            assert!(!files.iter().any(|path| path == forbidden), "{forbidden}");
        }
        let root = directory.path().canonicalize().unwrap();
        assert_eq!(
            paths(&root, Some("source.rs")).unwrap().0,
            vec!["source.rs"]
        );
        assert!(paths(&root, Some("node_modules")).is_err());
        assert!(paths(&root, Some("ignored.rs")).unwrap().0.is_empty());
    }

    #[test]
    fn source_read_rejects_private_paths_binary_and_keys() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let root = root.to_str().unwrap();
        fs::write(directory.path().join("source.rs"), "visible\n").unwrap();
        fs::write(directory.path().join(".env"), "secret\n").unwrap();
        fs::write(directory.path().join("binary"), b"a\0b").unwrap();
        fs::write(
            directory.path().join("source.txt"),
            "-----BEGIN PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("config.txt"),
            "https://user:synthetic-secret@example.invalid/path\n",
        )
        .unwrap();
        assert_eq!(file_text(root, "source.rs").unwrap(), "visible\n");
        for path in [".env", "../source.rs", "binary", "source.txt", "config.txt"] {
            assert!(file_text(root, path).is_err(), "{path}");
        }
    }
}
