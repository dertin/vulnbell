use crate::model::Instance;
use anyhow::{Context, Result, bail};

pub(crate) fn recognizes(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "uv.lock" | "poetry.lock" | "pdm.lock" | "pipfile.lock" | "pylock.toml"
    ) {
        return true;
    }
    if name.ends_with(".py.lock") || name.ends_with(".pyw.lock") {
        return true;
    }
    name.strip_prefix("pylock.")
        .and_then(|value| value.strip_suffix(".toml"))
        .is_some_and(|value| !value.is_empty() && !value.contains('.'))
}

fn toml_candidates(name: &str, bytes: &[u8]) -> Result<(Vec<(String, String)>, usize)> {
    let text = std::str::from_utf8(bytes)?;
    let document: toml::Value = toml::from_str(text)?;
    let root = document.as_table().context("Python lock must be a table")?;
    let lower_name = name.to_ascii_lowercase();
    let field = if lower_name == "uv.lock"
        || lower_name.ends_with(".py.lock")
        || lower_name.ends_with(".pyw.lock")
    {
        if root.get("version").and_then(toml::Value::as_integer) != Some(1) {
            bail!("unsupported uv lock version");
        }
        if let Some(revision) = root.get("revision")
            && !matches!(revision.as_integer(), Some(1..=5))
        {
            bail!("unsupported uv lock revision");
        }
        "package"
    } else if name.eq_ignore_ascii_case("pdm.lock") {
        let version = root
            .get("metadata")
            .and_then(|v| v.get("lock_version"))
            .and_then(toml::Value::as_str)
            .context("PDM lock version missing")?;
        if !matches!(version, "4.5.0" | "4.5.1") {
            bail!("unsupported PDM lock version");
        }
        "package"
    } else if name.eq_ignore_ascii_case("poetry.lock") {
        let version = root
            .get("metadata")
            .and_then(|v| v.get("lock-version"))
            .and_then(toml::Value::as_str)
            .context("Poetry lock version missing")?;
        if !matches!(version, "1.0" | "1.1" | "2.0" | "2.1") {
            bail!("unsupported Poetry lock version");
        }
        "package"
    } else {
        if root.get("lock-version").and_then(toml::Value::as_str) != Some("1.0") {
            bail!("unsupported pylock version");
        }
        "packages"
    };
    let packages = root
        .get(field)
        .and_then(toml::Value::as_array)
        .context("Python lock packages missing or invalid")?;
    let mut candidates = Vec::new();
    let mut unsupported = 0;
    for package in packages {
        let Some(package) = package.as_table() else {
            unsupported += 1;
            continue;
        };
        match (
            package.get("name").and_then(toml::Value::as_str),
            package.get("version").and_then(toml::Value::as_str),
        ) {
            (Some(name), Some(version)) => candidates.push((name.to_owned(), version.to_owned())),
            _ => unsupported += 1,
        }
    }
    Ok((candidates, unsupported))
}

fn pipfile_candidates(bytes: &[u8]) -> Result<(Vec<(String, String)>, usize)> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let document: serde_json::Value = serde_json::from_slice(bytes)?;
    let root = document
        .as_object()
        .context("Pipfile lock must be an object")?;
    if root
        .get("_meta")
        .and_then(|v| v.get("pipfile-spec"))
        .and_then(serde_json::Value::as_u64)
        != Some(6)
    {
        bail!("unsupported Pipfile lock version");
    }
    let mut candidates = Vec::new();
    let mut unsupported = 0;
    for (section, entries) in root {
        if section == "_meta" {
            continue;
        }
        let entries = entries.as_object().context("invalid Pipfile lock group")?;
        for (name, entry) in entries {
            match entry
                .get("version")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| v.strip_prefix("=="))
            {
                Some(version) => candidates.push((name.clone(), version.to_owned())),
                None => unsupported += 1,
            }
        }
    }
    Ok((candidates, unsupported))
}

pub(super) fn parse(
    bytes: &[u8],
    codebase: &str,
    path: &str,
    budget: usize,
) -> Result<(Vec<Instance>, String)> {
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|v| v.to_str())
        .context("invalid Python lock path")?;
    let (candidates, mut unsupported) = if name.eq_ignore_ascii_case("Pipfile.lock") {
        pipfile_candidates(bytes)?
    } else {
        toml_candidates(name, bytes)?
    };
    let mut input = String::new();
    for (name, version) in candidates {
        if name.is_empty()
            || version.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.+!".contains(&b))
        {
            unsupported += 1;
            continue;
        }
        input.push_str(&name);
        input.push_str("==");
        input.push_str(&version);
        input.push('\n');
    }
    let (mut instances, detail) =
        super::requirements::parse(input.as_bytes(), codebase, path, budget)?;
    let hash = crate::digest(bytes);
    for instance in &mut instances {
        instance.provenance.sha256 = hash.clone();
        instance.provenance.line = None;
        instance.provenance.resolution = Some("lock target and environment not evaluated".into());
    }
    Ok((
        instances,
        format!(
            "{detail}; {unsupported} lock entries require local review; lock targets and groups are not evaluated"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::{parse, recognizes};
    use crate::model::Origin;

    #[test]
    fn structured_locks_keep_versions_local_and_targets_unknown() {
        let fixtures = [
            (
                "uv.lock",
                "version = 1\n[[package]]\nname = 'example'\nversion = '1.2.3'\nsource = { registry = 'https://user:secret@example.invalid' }\n",
            ),
            (
                "script.py.lock",
                "version = 1\nrevision = 3\n[[package]]\nname = 'example'\nversion = '1.2.3'\n",
            ),
            (
                "pdm.lock",
                "[metadata]\nlock_version = '4.5.1'\n[[package]]\nname = 'example'\nversion = '1.2.3'\n",
            ),
            (
                "poetry.lock",
                "[[package]]\nname = 'example'\nversion = '1.2.3'\n[metadata]\nlock-version = '2.1'\n",
            ),
            (
                "pylock.toml",
                "lock-version = '1.0'\n[[packages]]\nname = 'example'\nversion = '1.2.3'\n",
            ),
            (
                "pylock.test.toml",
                "lock-version = '1.0'\n[[packages]]\nname = 'example'\nversion = '1.2.3'\n",
            ),
            (
                "Pipfile.lock",
                r#"{"_meta":{"pipfile-spec":6},"default":{"example":{"version":"==1.2.3","index":"https://user:secret@example.invalid"}},"develop":{}}"#,
            ),
        ];
        for (name, content) in fixtures {
            assert!(recognizes(name));
            let (items, detail) = parse(content.as_bytes(), "/codebase", name, 10).unwrap();
            assert_eq!(items.len(), 1, "{name}");
            assert_eq!(items[0].reference, "python-requirement:example");
            assert_eq!(items[0].resolved_version.as_deref(), Some("1.2.3"));
            assert_eq!(items[0].origin, Origin::Declared);
            assert_eq!(items[0].purl, None);
            assert_eq!(
                items[0].provenance.sha256,
                crate::digest(content.as_bytes())
            );
            assert_eq!(items[0].provenance.line, None);
            assert_eq!(
                items[0].provenance.resolution.as_deref(),
                Some("lock target and environment not evaluated")
            );
            assert!(!format!("{items:?}{detail}").contains("secret"));
        }
    }

    #[test]
    fn unsupported_versions_and_unresolved_entries_stay_visible() {
        assert!(parse(b"version = 9\n", "/codebase", "uv.lock", 10).is_err());
        assert!(parse(b"version = 1\nrevision = 6\n", "/codebase", "uv.lock", 10).is_err());
        assert!(parse(b"lock-version = '2.0'\n", "/codebase", "pylock.toml", 10).is_err());
        let content = b"version = 1\n[[package]]\nname = 'missing-version'\n[[package]]\nname = 'example'\nversion = '1.0'\n";
        let (items, detail) = parse(content, "/codebase", "uv.lock", 10).unwrap();
        assert_eq!(items.len(), 1);
        assert!(detail.contains("1 lock entries require local review"));
        assert!(!recognizes("pylock.a.b.toml"));
    }

    #[test]
    fn pipfile_with_utf8_bom_is_supported() {
        let content = b"\xef\xbb\xbf{\"_meta\":{\"pipfile-spec\":6},\"default\":{\"example\":{\"version\":\"==1.2.3\"}}}";
        let (items, _) = parse(content, "/codebase", "Pipfile.lock", 10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].provenance.sha256, crate::digest(content));
    }
}
