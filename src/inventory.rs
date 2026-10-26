use crate::model::{Coverage, CoverageState, Instance, Origin, Provenance};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct Inventory {
    pub instances: Vec<Instance>,
    pub coverage: Vec<Coverage>,
}
#[derive(Debug, serde::Serialize, Deserialize)]
pub struct LockedPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub direct: Option<bool>,
    pub resolution: Option<String>,
    pub artifact_integrity: Option<String>,
}
#[derive(Deserialize)]
struct CargoLock {
    version: Option<u32>,
    package: Vec<CargoPackage>,
}
#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}
#[derive(Deserialize)]
struct ComposerLock {
    packages: Vec<ComposerPackage>,
    #[serde(rename = "packages-dev", default)]
    packages_dev: Vec<ComposerPackage>,
}
#[derive(Deserialize)]
struct ComposerPackage {
    name: String,
    version: String,
}
#[derive(Deserialize)]
struct NpmLock {
    #[serde(rename = "lockfileVersion")]
    version: u32,
    #[serde(default)]
    packages: BTreeMap<String, NpmPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmV1Package>,
}
#[derive(Deserialize)]
struct NpmV1Package {
    version: String,
    integrity: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmV1Package>,
}
#[derive(Deserialize)]
struct NpmPackage {
    name: Option<String>,
    version: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    link: bool,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct PnpmLock {
    #[serde(rename = "lockfileVersion")]
    version: serde_json::Value,
    #[serde(default)]
    packages: BTreeMap<String, serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct Cyclone {
    #[serde(rename = "bomFormat")]
    format: String,
    #[serde(rename = "specVersion")]
    version: String,
    #[serde(default)]
    components: Vec<BomComponent>,
}
#[derive(Deserialize)]
struct BomComponent {
    purl: Option<String>,
    #[serde(default)]
    components: Vec<BomComponent>,
}
#[derive(Deserialize)]
struct Spdx {
    #[serde(rename = "spdxVersion")]
    version: String,
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}
#[derive(Deserialize)]
struct SpdxPackage {
    #[serde(rename = "externalRefs", default)]
    refs: Vec<ExternalRef>,
}
#[derive(Deserialize)]
struct ExternalRef {
    #[serde(rename = "referenceType")]
    kind: String,
    #[serde(rename = "referenceLocator")]
    locator: String,
}

fn locked(ecosystem: &str, name: String, version: String) -> LockedPackage {
    LockedPackage {
        ecosystem: ecosystem.into(),
        name,
        version,
        direct: None,
        resolution: None,
        artifact_integrity: None,
    }
}
fn purl_package(value: &str) -> Result<LockedPackage> {
    let parsed: packageurl::PackageUrl<'_> = value.parse()?;
    let version = parsed
        .version()
        .context("SBOM PURL has no version")?
        .to_owned();
    let name = match parsed.namespace() {
        Some(namespace) => format!("{namespace}/{}", parsed.name()),
        None => parsed.name().to_owned(),
    };
    Ok(locked(parsed.ty(), name, version))
}
pub fn parse_lock(filename: &str, bytes: &[u8]) -> Result<Vec<LockedPackage>> {
    let mut packages = Vec::new();
    match filename {
        "Cargo.lock" => {
            let text = std::str::from_utf8(bytes)?;
            let lock: CargoLock = toml::from_str(text)?;
            if lock.version.is_some_and(|version| version > 4) {
                bail!("unsupported Cargo lock version");
            }
            for package in lock.package {
                if let Some(source) = package.source.as_deref()
                    && (source.starts_with("registry+") || source.starts_with("sparse+"))
                {
                    if ![
                        "registry+https://github.com/rust-lang/crates.io-index",
                        "sparse+https://index.crates.io/",
                    ]
                    .contains(&source)
                    {
                        bail!("custom Cargo registry has no verified crates.io equivalence");
                    }
                    let mut target = locked("cargo", package.name, package.version);
                    target.resolution = package.source;
                    target.artifact_integrity = package.checksum;
                    packages.push(target);
                }
                // Local/git packages do not inherit registry identity merely from their names.
            }
        }
        "composer.lock" => {
            let lock: ComposerLock = serde_json::from_slice(bytes)?;
            for package in lock.packages.into_iter().chain(lock.packages_dev) {
                packages.push(locked("composer", package.name, package.version));
            }
        }
        "package-lock.json" => {
            let lock: NpmLock = serde_json::from_slice(bytes)?;
            if lock.version == 1 {
                fn visit(
                    dependencies: BTreeMap<String, NpmV1Package>,
                    packages: &mut Vec<LockedPackage>,
                    depth: usize,
                    parent: &str,
                ) -> Result<()> {
                    if depth > 64 {
                        bail!("npm dependency nesting limit");
                    }
                    for (name, package) in dependencies {
                        if package.version.starts_with("file:")
                            || package.version.starts_with("git")
                        {
                            bail!("nonregistry npm v1 identity unsupported");
                        }
                        let path = format!("{parent}node_modules/{name}");
                        let mut target = locked("npm", name, package.version);
                        target.direct = Some(depth == 0);
                        target.resolution = Some(path.clone());
                        target.artifact_integrity = package.integrity;
                        packages.push(target);
                        visit(
                            package.dependencies,
                            packages,
                            depth + 1,
                            &format!("{path}/"),
                        )?;
                    }
                    Ok(())
                }
                visit(lock.dependencies, &mut packages, 0, "")?;
            } else if matches!(lock.version, 2 | 3) {
                let direct_names: std::collections::HashSet<String> = lock
                    .packages
                    .get("")
                    .map(|root| root.dependencies.keys().cloned().collect())
                    .unwrap_or_default();
                for (path, package) in lock.packages {
                    if path.is_empty() || package.link {
                        continue;
                    }
                    let name = match package.name {
                        Some(name) => name,
                        None => path
                            .rsplit_once("node_modules/")
                            .context("npm package path has no registry name")?
                            .1
                            .to_owned(),
                    };
                    let version = package.version.context("npm package missing version")?;
                    if version.starts_with("file:") || version.starts_with("git") {
                        bail!("nonregistry npm package: identity unresolved");
                    }
                    let direct = direct_names
                        .iter()
                        .any(|declared_name| path == format!("node_modules/{declared_name}"));
                    let mut target = locked("npm", name, version);
                    target.direct = Some(direct);
                    target.resolution = Some(path);
                    target.artifact_integrity = package.integrity;
                    packages.push(target);
                }
            } else {
                bail!("unsupported npm lockfileVersion");
            }
        }
        "pnpm-lock.yaml" => {
            let lock: PnpmLock = crate::parse_yaml(bytes)?;
            let version = match lock.version {
                serde_json::Value::String(value) => value,
                serde_json::Value::Number(value) => value.to_string(),
                _ => bail!("invalid pnpm lock version"),
            };
            if !version.starts_with("9.")
                && version != "9"
                && !version.starts_with("6.")
                && version != "6"
            {
                bail!("supported pnpm lock versions: 6 and 9");
            }
            for (key, _) in lock.packages {
                let identity = key
                    .trim_start_matches('/')
                    .split('(')
                    .next()
                    .context("empty pnpm identity")?;
                let (name, package_version) = identity
                    .rsplit_once('@')
                    .context("pnpm registry key must contain @version")?;
                let mut target = locked("npm", name.into(), package_version.into());
                target.resolution = Some(key);
                packages.push(target);
            }
        }
        "yarn.lock" => {
            let text = std::str::from_utf8(bytes)?;
            if !text.contains("# yarn lockfile v1") {
                bail!("only Yarn classic v1 is supported");
            }
            let mut name: Option<String> = None;
            for line in text.lines() {
                if !line.starts_with(' ') && line.ends_with(':') && !line.starts_with('#') {
                    let key = line
                        .trim_end_matches(':')
                        .split(", ")
                        .next()
                        .context("empty yarn key")?
                        .trim_matches('"');
                    let (package_name, _) =
                        key.rsplit_once('@').context("invalid Yarn selector")?;
                    name = Some(package_name.into());
                } else if let Some(value) = line.trim_start().strip_prefix("version ") {
                    let package_name = name.take().context("Yarn version without selector")?;
                    packages.push(locked("npm", package_name, value.trim_matches('"').into()));
                }
            }
            if packages.is_empty() && text.lines().any(|line| line.ends_with(':')) {
                bail!("unparsed Yarn entries");
            }
        }
        _ => {
            let value: serde_json::Value = serde_json::from_slice(bytes)?;
            if value.get("bomFormat").is_some() {
                let bom: Cyclone = serde_json::from_value(value)?;
                if bom.format != "CycloneDX"
                    || !["1.4", "1.5", "1.6"].contains(&bom.version.as_str())
                {
                    bail!("unsupported CycloneDX version");
                }
                fn visit(
                    components: Vec<BomComponent>,
                    packages: &mut Vec<LockedPackage>,
                    depth: usize,
                ) -> Result<()> {
                    if depth > 32 {
                        bail!("SBOM nesting limit");
                    }
                    for component in components {
                        if let Some(purl) = component.purl {
                            packages.push(purl_package(&purl)?);
                        }
                        visit(component.components, packages, depth + 1)?;
                    }
                    Ok(())
                }
                visit(bom.components, &mut packages, 0)?;
            } else {
                let bom: Spdx = serde_json::from_value(value)?;
                if !["SPDX-2.2", "SPDX-2.3"].contains(&bom.version.as_str()) {
                    bail!("unsupported SPDX version");
                }
                for package in bom.packages {
                    for reference in package.refs {
                        if reference.kind == "purl" {
                            packages.push(purl_package(&reference.locator)?);
                        }
                    }
                }
            }
        }
    }
    if packages.len() > 100_000 {
        bail!("package count exceeds 100000");
    }
    Ok(packages)
}
pub fn discover(
    workspaces: &[String],
    profile_path: &Path,
    store: &crate::store::Store,
    instance_budget: usize,
) -> Inventory {
    let mut inventory = Inventory::default();
    let base = profile_path.parent().unwrap_or(Path::new("."));
    let mut visited = std::collections::HashSet::new();
    let mut file_count = 0;
    let mut total_bytes = 0;
    'workspaces: for workspace in workspaces {
        let root = base.join(workspace);
        let root: PathBuf = match root.canonicalize() {
            Ok(root) if root.is_dir() && !root.starts_with(crate::store::data_root()) => root,
            _ => {
                inventory.coverage.push(Coverage::new(
                    "workspace",
                    workspace,
                    CoverageState::Unavailable,
                    "workspace missing or not a directory",
                ));
                continue;
            }
        };
        let walker = ignore::WalkBuilder::new(&root)
            .hidden(false)
            .follow_links(false)
            .max_depth(Some(32))
            .filter_entry(|entry| {
                ![
                    ".git",
                    "node_modules",
                    "vendor",
                    ".venv",
                    "target",
                    ".cache",
                    "dist",
                    "build",
                ]
                .contains(&entry.file_name().to_string_lossy().as_ref())
            })
            .build();
        let mut supported_files = 0;
        for entry in walker {
            if total_bytes > 128 * 1024 * 1024 {
                inventory.coverage.push(Coverage::new(
                    "inventory",
                    workspace,
                    CoverageState::Partial,
                    "aggregate inventory byte budget exhausted; remaining files were not read",
                ));
                break 'workspaces;
            }
            if inventory.instances.len() >= instance_budget {
                inventory.coverage.push(Coverage::new(
                    "inventory",
                    workspace,
                    CoverageState::Partial,
                    "shared instance budget exhausted; remaining files were not reviewed",
                ));
                break 'workspaces;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    inventory.coverage.push(Coverage::new(
                        "workspace",
                        workspace,
                        CoverageState::Partial,
                        "directory traversal failed",
                    ));
                    continue;
                }
            };
            file_count += 1;
            if file_count > 100_000 {
                inventory.coverage.push(Coverage::new(
                    "workspace",
                    workspace,
                    CoverageState::Partial,
                    "100000 entry discovery limit",
                ));
                break 'workspaces;
            }
            if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            let supported = [
                "Cargo.lock",
                "composer.lock",
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bom.json",
                "sbom.json",
            ]
            .contains(&name.as_ref())
                || name.ends_with(".cdx.json")
                || name.ends_with(".spdx.json");
            if !supported {
                if [
                    "go.mod",
                    "go.sum",
                    "poetry.lock",
                    "uv.lock",
                    "Pipfile.lock",
                    "requirements.txt",
                ]
                .contains(&name.as_ref())
                {
                    inventory.coverage.push(Coverage::new("inventory",&entry.path().strip_prefix(&root).unwrap_or(entry.path()).to_string_lossy(),CoverageState::Unsupported,"detected ecosystem lock/manifest is not implemented; provide a supported SBOM or explicit components"));
                }
                continue;
            }
            supported_files += 1;
            if !visited.insert(entry.path().to_owned()) {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string();
            let result = crate::read_limited(entry.path(), 32 * 1024 * 1024).and_then(|bytes| {
                total_bytes += bytes.len();
                if total_bytes > 128 * 1024 * 1024 {
                    bail!("aggregate inventory byte budget exhausted");
                }
                use rusqlite::OptionalExtension;
                let hash = crate::digest(&bytes);
                let key = format!("parser-v3:{name}:{hash}");
                let cached: Option<String> = store
                    .connection
                    .query_row(
                        "SELECT body FROM inventory_cache WHERE key=?1",
                        [&key],
                        |row| row.get(0),
                    )
                    .optional()?;
                let packages: Vec<LockedPackage> = match cached {
                    Some(body) => serde_json::from_str(&body)?,
                    None => {
                        let packages = parse_lock(&name, &bytes)?;
                        store.connection.execute(
                            "INSERT OR REPLACE INTO inventory_cache VALUES (?1,?2)",
                            rusqlite::params![key, serde_json::to_string(&packages)?],
                        )?;
                        packages
                    }
                };
                Ok((packages, hash))
            });
            match result {
                Ok((packages, hash)) => {
                    let mut occurrences: BTreeMap<String, usize> = BTreeMap::new();
                    for package in packages {
                        if inventory.instances.len() >= instance_budget {
                            inventory.coverage.push(Coverage::new(
                                "inventory",
                                &relative,
                                CoverageState::Partial,
                                "shared instance budget exhausted inside lockfile",
                            ));
                            break 'workspaces;
                        }
                        let (namespace, package_name) = match package.name.rsplit_once('/') {
                            Some((namespace, name)) => (Some(namespace), name),
                            None => (None, package.name.as_str()),
                        };
                        let mut purl =
                            match packageurl::PackageUrl::new(&package.ecosystem, package_name) {
                                Ok(purl) => purl,
                                Err(_) => {
                                    inventory.coverage.push(Coverage::new(
                                        "inventory",
                                        &relative,
                                        CoverageState::Partial,
                                        "invalid package identity",
                                    ));
                                    continue;
                                }
                            };
                        if let Some(namespace) = namespace
                            && purl.with_namespace(namespace).is_err()
                        {
                            inventory.coverage.push(Coverage::new(
                                "inventory",
                                &relative,
                                CoverageState::Partial,
                                "invalid package namespace",
                            ));
                            continue;
                        }
                        if purl.validate().is_err() {
                            inventory.coverage.push(Coverage::new(
                                "inventory",
                                &relative,
                                CoverageState::Partial,
                                "invalid package identity",
                            ));
                            continue;
                        }
                        let reference = purl.to_string();
                        let identity = format!(
                            "{:?}:{relative:?}:{reference:?}:{:?}:{:?}",
                            root, package.version, package.resolution
                        );
                        let occurrence = occurrences.entry(identity.clone()).or_default();
                        let id = crate::digest(format!("{identity}:{occurrence}").as_bytes());
                        *occurrence += 1;
                        inventory.instances.push(Instance {
                            id,
                            reference: reference.clone(),
                            requested_version: Some(package.version.clone()),
                            resolved_version: Some(package.version),
                            origin: Origin::Locked,
                            provenance: Provenance {
                                path: Some(relative.clone()),
                                sha256: hash.clone(),
                                observed_at: crate::now(),
                                workspace: Some(workspace.clone()),
                                direct: package.direct,
                                resolution: package.resolution,
                                artifact_integrity: package.artifact_integrity,
                            },
                            purl: Some(reference),
                            cpe_product: None,
                            upstream: None,
                            identity_evidence: Vec::new(),
                        });
                    }
                    inventory.coverage.push(Coverage::new("inventory", &relative, CoverageState::Checked, "registry packages parsed; directness is included when available; local/git dependencies have no registry equivalence"));
                }
                Err(error) => inventory.coverage.push(Coverage::new(
                    "inventory",
                    &relative,
                    CoverageState::Partial,
                    safe_inventory_error(&error),
                )),
            }
        }
        if supported_files == 0 {
            inventory.coverage.push(Coverage::new("inventory",workspace,CoverageState::Partial,"no supported lockfile/SBOM found; this workspace was not evaluated for exact dependency versions"));
        }
    }
    inventory
}

fn safe_inventory_error(error: &anyhow::Error) -> String {
    if let Some(error) = error.downcast_ref::<serde_json::Error>() {
        return format!(
            "JSON inventory parse failed at line {}, column {}; source content omitted",
            error.line(),
            error.column()
        );
    }
    if let Some(error) = error.downcast_ref::<toml::de::Error>() {
        return format!(
            "TOML inventory parse failed at byte span {:?}; source content omitted",
            error.span()
        );
    }
    if let Some(error) = error.downcast_ref::<serde_saphyr::Error>() {
        return match error.location() {
            Some(location) => format!(
                "YAML inventory parse failed at line {}, column {}; source content omitted",
                location.line(),
                location.column()
            ),
            None => "YAML inventory parse failed; source content omitted".into(),
        };
    }
    error.to_string()
}
