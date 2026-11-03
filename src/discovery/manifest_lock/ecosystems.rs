use super::*;

pub(super) fn declaration_section(
    files: &mut Files,
    root: &str,
    path: &str,
    line: usize,
    name: &str,
) -> Option<bool> {
    let lines = files.cargo_lines(root, path)?;
    let source = lines.get(line.checked_sub(1)?)?;
    let bytes = files.bytes(root, path)?;
    let content = std::str::from_utf8(&bytes[source.start..source.end])
        .ok()?
        .trim();
    let tail = content.strip_prefix(name)?;
    tail.starts_with(|character: char| {
        character.is_ascii_whitespace() || character == '.' || character == '='
    })
    .then_some(source.workspace)
    .flatten()
}

fn dependency<'a>(
    manifest: &'a toml::Value,
    name: &str,
    workspace: bool,
) -> Option<&'a toml::Value> {
    if workspace {
        return manifest.get("workspace")?.get("dependencies")?.get(name);
    }
    let mut matches = ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|section| manifest.get(section).and_then(|value| value.get(name)));
    let first = matches.next()?;
    matches.all(|value| value == first).then_some(first)
}

fn cargo_requirement(value: &toml::Value) -> Option<semver::VersionReq> {
    let version = if let Some(version) = value.as_str() {
        version
    } else {
        let table = value.as_table()?;
        if [
            "path",
            "git",
            "registry",
            "registry-index",
            "package",
            "workspace",
        ]
        .iter()
        .any(|key| table.contains_key(*key))
        {
            return None;
        }
        table.get("version")?.as_str()?
    };
    semver::VersionReq::parse(version).ok()
}

fn member_of_workspace(root: &toml::Value, member: &str) -> bool {
    let Some(workspace) = root.get("workspace") else {
        return false;
    };
    let matches = |value: &toml::Value| {
        value.as_str().is_some_and(|pattern| {
            !pattern.starts_with('/')
                && !pattern.split('/').any(|part| part == "..")
                && globset::GlobBuilder::new(pattern)
                    .literal_separator(true)
                    .build()
                    .is_ok_and(|glob| glob.compile_matcher().is_match(member))
        })
    };
    let excluded = workspace
        .get("exclude")
        .and_then(toml::Value::as_array)
        .is_some_and(|values| values.iter().any(matches));
    !excluded
        && workspace
            .get("members")
            .and_then(toml::Value::as_array)
            .is_some_and(|values| values.iter().any(matches))
}

fn package_version<'a>(manifest: &'a toml::Value, workspace: &'a toml::Value) -> Option<&'a str> {
    let version = manifest.get("package")?.get("version")?;
    if version.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
        workspace
            .get("workspace")?
            .get("package")?
            .get("version")?
            .as_str()
    } else {
        version.as_str()
    }
}

pub(super) fn cargo_link(observed: &Instance, lock: &Instance, files: &mut Files) -> bool {
    let (Some(root), Some(manifest_path), Some(lock_path), Some(version)) = (
        observed.provenance.codebase.as_deref(),
        observed.provenance.path.as_deref(),
        lock.provenance.path.as_deref(),
        lock.resolved_version.as_deref(),
    ) else {
        return false;
    };
    if !safe_path(manifest_path)
        || !safe_path(lock_path)
        || Path::new(manifest_path)
            .file_name()
            .and_then(|value| value.to_str())
            != Some("Cargo.toml")
        || Path::new(lock_path)
            .file_name()
            .and_then(|value| value.to_str())
            != Some("Cargo.lock")
        || lock.provenance.direct != Some(true)
        || !matches!(
            lock.provenance.resolution.as_deref(),
            Some(
                "registry+https://github.com/rust-lang/crates.io-index"
                    | "sparse+https://index.crates.io/"
            )
        )
        || !lock
            .provenance
            .artifact_integrity
            .as_deref()
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return false;
    }
    let Some(name) = observed.reference.strip_prefix("pkg:cargo/") else {
        return false;
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return false;
    }
    let Some(section_is_workspace) = observed
        .provenance
        .line
        .and_then(|line| declaration_section(files, root, manifest_path, line, name))
    else {
        return false;
    };
    let Some(manifest) = files.toml(root, manifest_path) else {
        return false;
    };
    let manifest_dir = Path::new(manifest_path).parent().unwrap_or(Path::new(""));
    let lock_dir = Path::new(lock_path).parent().unwrap_or(Path::new(""));
    let Ok(member) = manifest_dir.strip_prefix(lock_dir) else {
        return false;
    };
    let Ok(version) = semver::Version::parse(version) else {
        return false;
    };
    if member.as_os_str().is_empty() {
        let requirement = dependency(&manifest, name, section_is_workspace);
        if !requirement
            .and_then(cargo_requirement)
            .is_some_and(|req| req.matches(&version))
        {
            return false;
        }
        if section_is_workspace {
            return manifest.get("workspace").is_some();
        }
        let Some(package_name) = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
        else {
            return false;
        };
        let Some(package_version) = package_version(&manifest, &manifest) else {
            return false;
        };
        return files.cargo_graph(root, lock_path).is_some_and(|graph| {
            graph.depends_on(package_name, package_version, name, &version.to_string())
        });
    }
    let member_path = crate::slash_path(member);
    if manifest
        .get("package")
        .and_then(|value| value.get("workspace"))
        .is_some()
    {
        return false;
    }
    let root_manifest_path = crate::slash_path(&lock_dir.join("Cargo.toml"));
    let Some(root_manifest) = files.toml(root, &root_manifest_path) else {
        return false;
    };
    if !member_of_workspace(&root_manifest, &member_path) {
        return false;
    }
    if section_is_workspace {
        return false;
    }
    let Some(member_name) = manifest
        .get("package")
        .and_then(|value| value.get("name"))
        .and_then(toml::Value::as_str)
    else {
        return false;
    };
    let Some(member_version) = package_version(&manifest, &root_manifest) else {
        return false;
    };
    let Some(member_dependency) = dependency(&manifest, name, false) else {
        return false;
    };
    let requirement = if member_dependency
        .get("workspace")
        .and_then(toml::Value::as_bool)
        == Some(true)
    {
        let Some(table) = member_dependency.as_table() else {
            return false;
        };
        if table.keys().any(|key| {
            !["workspace", "features", "optional", "default-features"].contains(&key.as_str())
        }) {
            return false;
        }
        dependency(&root_manifest, name, true).and_then(cargo_requirement)
    } else {
        cargo_requirement(member_dependency)
    };
    if !requirement.is_some_and(|requirement| requirement.matches(&version)) {
        return false;
    }
    let Some(graph) = files.cargo_graph(root, lock_path) else {
        return false;
    };
    graph.depends_on(member_name, member_version, name, &version.to_string())
}

pub(super) fn workspace_declaration(
    observed: &Instance,
    lock: &Instance,
    files: &mut Files,
) -> bool {
    let (Some(root), Some(path), Some(line), Some(lock_path), Some(name)) = (
        observed.provenance.codebase.as_deref(),
        observed.provenance.path.as_deref(),
        observed.provenance.line,
        lock.provenance.path.as_deref(),
        observed.reference.strip_prefix("pkg:cargo/"),
    ) else {
        return false;
    };
    Path::new(path).parent() == Path::new(lock_path).parent()
        && declaration_section(files, root, path, line, name) == Some(true)
}

pub(super) fn inherits_workspace(observed: &Instance, files: &mut Files) -> bool {
    let (Some(root), Some(path), Some(name)) = (
        observed.provenance.codebase.as_deref(),
        observed.provenance.path.as_deref(),
        observed.reference.strip_prefix("pkg:cargo/"),
    ) else {
        return false;
    };
    files.toml(root, path).and_then(|manifest| {
        dependency(&manifest, name, false)?
            .get("workspace")?
            .as_bool()
    }) == Some(true)
}

pub(super) fn npm_link(observed: &Instance, lock: &Instance, files: &mut Files) -> bool {
    use base64::Engine;
    let (Some(root), Some(manifest_path), Some(lock_path), Some(version), Some(resolution)) = (
        observed.provenance.codebase.as_deref(),
        observed.provenance.path.as_deref(),
        lock.provenance.path.as_deref(),
        lock.resolved_version.as_deref(),
        lock.provenance.resolution.as_deref(),
    ) else {
        return false;
    };
    if !safe_path(manifest_path)
        || !safe_path(lock_path)
        || Path::new(manifest_path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("package.json")
        || Path::new(lock_path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("package-lock.json")
        || Path::new(manifest_path).parent() != Path::new(lock_path).parent()
        || lock.provenance.direct != Some(true)
    {
        return false;
    }
    let Some(name) = resolution.strip_prefix("node_modules/") else {
        return false;
    };
    if name.contains("/node_modules/") || name.is_empty() {
        return false;
    }
    let Some(line) = observed.provenance.line else {
        return false;
    };
    if files.json_key_line(root, manifest_path, name) != Some(line) {
        return false;
    }
    let Some(digest) = lock
        .provenance
        .artifact_integrity
        .as_deref()
        .and_then(|value| value.strip_prefix("sha512-"))
    else {
        return false;
    };
    if !base64::engine::general_purpose::STANDARD
        .decode(digest)
        .is_ok_and(|bytes| bytes.len() == 64)
    {
        return false;
    }
    let (Some(manifest), Some(lockfile)) =
        (files.json(root, manifest_path), files.json(root, lock_path))
    else {
        return false;
    };
    if !matches!(
        lockfile
            .get("lockfileVersion")
            .and_then(serde_json::Value::as_u64),
        Some(2 | 3)
    ) {
        return false;
    }
    let Some(packages) = lockfile.get("packages") else {
        return false;
    };
    let Some(package) = packages.get(resolution) else {
        return false;
    };
    if package.get("version").and_then(serde_json::Value::as_str) != Some(version)
        || package.get("integrity").and_then(serde_json::Value::as_str)
            != lock.provenance.artifact_integrity.as_deref()
        || package.get("link").and_then(serde_json::Value::as_bool) == Some(true)
        || package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|actual| actual != name)
    {
        return false;
    }
    let Some(url) = package
        .get("resolved")
        .and_then(serde_json::Value::as_str)
        .and_then(|url| url::Url::parse(url).ok())
    else {
        return false;
    };
    let basename = name.rsplit('/').next().unwrap_or(name);
    let expected_path = format!("/{name}/-/{basename}-{version}.tgz");
    if url.scheme() != "https"
        || url.host_str() != Some("registry.npmjs.org")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().replace("%40", "@") != expected_path
    {
        return false;
    }
    let Some(importer) = packages.get("") else {
        return false;
    };
    let Ok(version) = semver::Version::parse(version) else {
        return false;
    };
    let sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    let mut declarations = Vec::new();
    for section in sections {
        if let Some(value) = manifest.get(section).and_then(|section| section.get(name)) {
            let Some(value) = value.as_str() else {
                return false;
            };
            if importer
                .get(section)
                .and_then(|section| section.get(name))
                .and_then(serde_json::Value::as_str)
                != Some(value)
            {
                return false;
            }
            declarations.push(value);
        }
    }
    let [requirement] = declarations.as_slice() else {
        return false;
    };
    let raw = requirement
        .strip_prefix('^')
        .or_else(|| requirement.strip_prefix('~'))
        .unwrap_or(requirement);
    let Ok(exact) = semver::Version::parse(raw) else {
        return false;
    };
    if raw == *requirement {
        exact == version
    } else {
        semver::VersionReq::parse(requirement).is_ok_and(|req| req.matches(&version))
    }
}
