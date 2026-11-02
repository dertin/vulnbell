use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const MAX_OUTPUT: u64 = 512 * 1024;

fn executable(roots: &[String]) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH is unavailable")?;
    for directory in std::env::split_paths(&path).filter(|path| path.is_absolute()) {
        for name in if cfg!(windows) {
            &["codegraph.exe"][..]
        } else {
            &["codegraph"][..]
        } {
            let candidate = directory.join(name);
            if let Ok(candidate) = candidate.canonicalize()
                && candidate.is_file()
                && !roots.iter().any(|root| candidate.starts_with(root))
            {
                return Ok(candidate);
            }
        }
    }
    bail!("CodeGraph executable is unavailable outside the monitored codebase")
}

fn run(executable: &Path, root: &Path, roots: &[String], arguments: &[&str]) -> Result<Value> {
    run_with_timeout(executable, root, roots, arguments, 20)
}

fn run_with_timeout(
    executable: &Path,
    root: &Path,
    roots: &[String],
    arguments: &[&str],
    seconds: u64,
) -> Result<Value> {
    let mut command = Command::new(executable);
    command.env_clear().current_dir(root);
    let path = std::env::var_os("PATH").context("PATH is unavailable")?;
    let directories: Vec<_> = std::env::split_paths(&path)
        .filter(|path| path.is_absolute())
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| !roots.iter().any(|root| path.starts_with(root)))
        .collect();
    command.env("PATH", std::env::join_paths(directories)?);
    for name in ["HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("DO_NOT_TRACK", "1")
        .env("CODEGRAPH_NO_WATCH", "1")
        .env("CODEGRAPH_NO_PROMPT_HOOK", "1")
        .env("CODEGRAPH_NO_UPDATE_CHECK", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(arguments);
    let output = crate::process::run_bounded_agent(&mut command, seconds, MAX_OUTPUT)?;
    if !output.success || output.timed_out {
        bail!("CodeGraph query failed or exceeded its limits");
    }
    serde_json::from_slice(&output.stdout).context("CodeGraph returned invalid JSON")
}

fn validate_status(status: &Value, root: &Path) -> Result<Vec<String>> {
    let path = status
        .get("projectPath")
        .and_then(Value::as_str)
        .context("CodeGraph project path missing")?;
    if Path::new(path).canonicalize()? != root.canonicalize()?
        || status.get("initialized").and_then(Value::as_bool) != Some(true)
        || status.pointer("/index/state").and_then(Value::as_str) != Some("complete")
        || status
            .pointer("/index/reindexRecommended")
            .and_then(Value::as_bool)
            != Some(false)
        || status.pointer("/index/pendingRefs").and_then(Value::as_u64) != Some(0)
        || !status
            .get("lastIndexed")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        || !status.get("worktreeMismatch").is_some_and(Value::is_null)
        || ["added", "modified", "removed"].iter().any(|name| {
            status
                .pointer(&format!("/pendingChanges/{name}"))
                .and_then(Value::as_u64)
                != Some(0)
        })
    {
        bail!("CodeGraph index is incomplete, stale or belongs to another codebase");
    }
    let languages = status
        .get("languages")
        .and_then(Value::as_array)
        .context("CodeGraph language coverage missing")?;
    if languages.len() > 100 {
        bail!("CodeGraph language list exceeds limit");
    }
    languages
        .iter()
        .map(|value| {
            let value = value.as_str().context("invalid CodeGraph language")?;
            if value.is_empty()
                || value.len() > 40
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                bail!("invalid CodeGraph language");
            }
            Ok(value.to_owned())
        })
        .collect()
}

pub(crate) fn indexed_languages_with_timeout(
    root: &Path,
    roots: &[String],
    seconds: u64,
) -> Result<Vec<String>> {
    let root = root.canonicalize()?;
    let index = root.join(".codegraph");
    if !index.is_dir()
        || index.is_symlink()
        || ["codegraph.db", "codegraph.db-wal", "codegraph.db-shm"]
            .iter()
            .any(|name| index.join(name).is_symlink())
    {
        bail!("CodeGraph index is missing or uses symlinks");
    }
    let exe = executable(roots)?;
    let root_text = root.to_str().context("codebase path is not UTF-8")?;
    validate_status(
        &run_with_timeout(
            &exe,
            &root,
            roots,
            &["status", "--json", root_text],
            seconds,
        )?,
        &root,
    )
}

pub(super) fn search(
    root: &str,
    query: &str,
    files: &[String],
    relation: Option<&str>,
    roots: &[String],
) -> Result<Value> {
    if query.is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
        bail!("query must be 1..256 printable bytes");
    }
    let root = Path::new(root).canonicalize()?;
    let index = root.join(".codegraph");
    if !index.is_dir()
        || index.is_symlink()
        || ["codegraph.db", "codegraph.db-wal", "codegraph.db-shm"]
            .iter()
            .any(|name| index.join(name).is_symlink())
    {
        bail!("CodeGraph index is missing or uses symlinks");
    }
    let exe = executable(roots)?;
    let root_text = root.to_str().context("codebase path is not UTF-8")?;
    let status = run(&exe, &root, roots, &["status", "--json", root_text])?;
    let languages = validate_status(&status, &root)?;
    let operation = match relation {
        None => "query",
        Some("callers") => "callers",
        Some("callees") => "callees",
        Some(_) => bail!("relation must be callers or callees"),
    };
    let result = run(
        &exe,
        &root,
        roots,
        &[
            operation, "--path", root_text, "--limit", "20", "--json", "--", query,
        ],
    )?;
    let locations = if let Some(relation) = relation {
        verified_relations(&result, relation, root_text, files)?
    } else {
        verified_locations(&result, root_text, files)?
    };
    let after = run(&exe, &root, roots, &["status", "--json", root_text])?;
    validate_status(&after, &root)?;
    if status.get("lastIndexed") != after.get("lastIndexed") {
        bail!("CodeGraph index changed during query");
    }
    Ok(
        json!({"locations":locations,"indexed_languages":languages,"complete":false,"limitation":"Locations are navigation hints, not proof of reachability or complete language coverage. Read the source to verify them."}),
    )
}

fn verified_relations(
    result: &Value,
    relation: &str,
    root: &str,
    files: &[String],
) -> Result<Vec<Value>> {
    let rows = result
        .get(relation)
        .and_then(Value::as_array)
        .context("CodeGraph relations missing")?;
    let wrapped: Vec<Value> = rows.iter().map(|row| json!({"node": {"filePath": row.get("filePath"), "startLine": row.get("startLine"), "endLine": row.get("startLine")}})).collect();
    verified_locations(&json!(wrapped), root, files)
}

fn verified_locations(result: &Value, root: &str, files: &[String]) -> Result<Vec<Value>> {
    let rows = result
        .as_array()
        .context("CodeGraph query is not an array")?;
    if rows.len() > 20 {
        bail!("CodeGraph query exceeds result limit");
    }
    let mut locations = Vec::new();
    for row in rows {
        let Some(node) = row.get("node") else {
            continue;
        };
        let Some(path) = node.get("filePath").and_then(Value::as_str) else {
            continue;
        };
        if !files.iter().any(|candidate| candidate == path) {
            continue;
        }
        let Ok(source) = super::file_text(root, path) else {
            continue;
        };
        let Some(start) = node
            .get("startLine")
            .and_then(Value::as_u64)
            .filter(|line| *line > 0)
        else {
            continue;
        };
        let Some(end) = node
            .get("endLine")
            .and_then(Value::as_u64)
            .filter(|line| *line >= start && *line <= source.lines().count() as u64)
        else {
            continue;
        };
        locations.push(json!({"path":path,"start_line":start,"end_line":end}));
    }
    Ok(locations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_must_be_current_and_belong_to_the_requested_root() {
        let root = tempfile::tempdir().unwrap();
        let mut status = json!({"projectPath":root.path(), "initialized":true,
            "index":{"state":"complete","reindexRecommended":false,"pendingRefs":0},
            "lastIndexed":"2026-01-01T00:00:00Z",
            "pendingChanges":{"added":0,"modified":0,"removed":0},"worktreeMismatch":null,
            "languages":["rust","python","php"]});
        assert_eq!(
            validate_status(&status, root.path()).unwrap(),
            ["rust", "python", "php"]
        );
        status["pendingChanges"]["modified"] = 1.into();
        assert!(validate_status(&status, root.path()).is_err());
        status["pendingChanges"]["modified"] = 0.into();
        status["index"]["pendingRefs"] = 1.into();
        assert!(validate_status(&status, root.path()).is_err());
        status["index"]["pendingRefs"] = 0.into();
        status["projectPath"] = json!(root.path().parent().unwrap());
        assert!(validate_status(&status, root.path()).is_err());
    }

    #[test]
    fn symbol_results_exclude_unapproved_paths_and_never_expose_graph_contents() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn entry() {}\n").unwrap();
        std::fs::write(root.path().join(".env"), "private\n").unwrap();
        let rows = json!([
            {"node":{"filePath":"app.rs","startLine":1,"endLine":1,"signature":"sensitive data"}},
            {"node":{"filePath":".env","startLine":1,"endLine":1}},
            {"node":{"filePath":"../outside.rs","startLine":1,"endLine":1}},
            {"node":{"filePath":"app.rs","startLine":1,"endLine":99}}
        ]);
        let root = root.path().canonicalize().unwrap();
        let locations =
            verified_locations(&rows, root.to_str().unwrap(), &["app.rs".into()]).unwrap();
        assert_eq!(
            locations,
            vec![json!({"path":"app.rs","start_line":1,"end_line":1})]
        );
        assert!(
            !serde_json::to_string(&locations)
                .unwrap()
                .contains("sensitive data")
        );
    }

    #[test]
    fn relationships_are_bounded_to_visible_source_locations() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn handler() {}\n").unwrap();
        let data = json!({"callers":[{"filePath":"app.rs","startLine":1,"name":"do not expose"},{"filePath":".env","startLine":1},{"filePath":"../outside.rs","startLine":1}]});
        let locations = verified_relations(
            &data,
            "callers",
            root.path().to_str().unwrap(),
            &["app.rs".into()],
        )
        .unwrap();
        assert_eq!(
            locations,
            vec![json!({"path":"app.rs","start_line":1,"end_line":1})]
        );
        assert!(
            verified_relations(
                &data,
                "callees",
                root.path().to_str().unwrap(),
                &["app.rs".into()]
            )
            .is_err()
        );
    }
}
