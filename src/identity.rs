use crate::{
    model::{Coverage, CoverageState, EvidenceKind, Instance},
    network::Http,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    package: CrateMetadata,
}
#[derive(Deserialize)]
struct CrateMetadata {
    max_stable_version: String,
    repository: Option<String>,
}
#[derive(Deserialize)]
struct NpmVersion {
    name: String,
    version: String,
    repository: Option<RepositoryMetadata>,
}
#[derive(Deserialize)]
struct PypiResponse {
    info: PypiInfo,
    #[serde(default)]
    urls: Vec<PypiFile>,
}
#[derive(Deserialize)]
struct PypiInfo {
    name: String,
    version: String,
}
#[derive(Deserialize)]
struct PypiFile {
    digests: PypiDigests,
}
#[derive(Deserialize)]
struct PypiDigests {
    sha256: String,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum RepositoryMetadata {
    Url(String),
    Object { url: String },
}
#[derive(Deserialize)]
struct SparseCrateVersion {
    name: String,
    vers: String,
    #[serde(default)]
    yanked: bool,
}
#[derive(Deserialize)]
struct ComposerMetadata {
    packages: std::collections::BTreeMap<String, Vec<ComposerVersion>>,
}
#[derive(Deserialize)]
struct ComposerVersion {
    version: String,
    source: Option<ComposerSource>,
}
#[derive(Deserialize)]
struct ComposerSource {
    url: String,
}
#[derive(Deserialize)]
struct Wordpress {
    offers: Vec<WordpressOffer>,
}
#[derive(Deserialize)]
struct WordpressOffer {
    version: String,
    response: String,
}
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}
#[derive(Deserialize)]
struct PhpRelease {
    version: String,
}

pub fn normalized_version(value: &str) -> Result<semver::Version> {
    let mut text = value.trim_start_matches('v').to_owned();
    if text.split('.').count() == 2 {
        text.push_str(".0");
    }
    Ok(semver::Version::parse(&text)?)
}
pub fn resolve(
    instance: &mut Instance,
    http: &mut Http<'_>,
    verify_pypi_hashes: bool,
) -> Vec<Coverage> {
    let mut coverage = Vec::new();
    let result = resolve_inner(instance, http, verify_pypi_hashes);
    match result {
        Ok(()) => coverage.push(Coverage::new(
            "identity",
            &instance.id,
            if instance.resolved_version.is_some() {
                CoverageState::Checked
            } else {
                CoverageState::Unresolved
            },
            if instance.resolved_version.is_some() {
                "identity resolved; deployment is not inferred"
            } else {
                "unresolved_version: ask user for version; latest was not assumed"
            },
        )),
        Err(error) => coverage.push(Coverage::new(
            "identity",
            &instance.id,
            CoverageState::Partial,
            error.to_string(),
        )),
    }
    if instance.upstream.is_none() && instance.provenance.direct == Some(true) {
        let cargo_name = instance
            .purl
            .as_deref()
            .and_then(|value| value.parse::<packageurl::PackageUrl<'_>>().ok())
            .filter(|purl| purl.ty() == "cargo")
            .map(|purl| purl.name().to_owned());
        if let Some(name) = cargo_name {
            let result = http
                .get(&format!(
                    "https://crates.io/api/v1/crates/{}",
                    crate::sources::encode(&name)
                ))
                .and_then(|response| {
                    let metadata: CrateResponse = response.json()?;
                    instance.identity_evidence.push(http.store.record_evidence(
                        &response.body,
                        "registry_repository",
                        Some(response.url),
                        EvidenceKind::Identity,
                    )?);
                    Ok(metadata.package.repository.and_then(clean_repository))
                });
            match result {
                Ok(repository) => {
                    instance.upstream = repository;
                    coverage.push(Coverage::new(
                        "upstream_identity",
                        &instance.id,
                        if instance.upstream.is_some() {
                            CoverageState::Checked
                        } else {
                            CoverageState::Unresolved
                        },
                        "authoritative crate repository metadata; no artifact equivalence inferred",
                    ));
                }
                Err(error) => coverage.push(Coverage::new(
                    "upstream_identity",
                    &instance.id,
                    CoverageState::Partial,
                    error.to_string(),
                )),
            }
        }
    }
    coverage
}
fn resolve_inner(
    instance: &mut Instance,
    http: &mut Http<'_>,
    verify_pypi_hashes: bool,
) -> Result<()> {
    if instance.reference.starts_with("python-requirement:") && instance.python_lock.is_some() {
        if !verify_pypi_hashes {
            bail!("PyPI hash verification is not authorized in this monitor");
        }
        let lock = instance
            .python_lock
            .as_ref()
            .context("Python lock metadata missing")?;
        if !lock.source_eligible {
            bail!(
                "Python lock contains source options or ambiguous includes; public identity not verified"
            );
        }
        let name = instance
            .reference
            .strip_prefix("python-requirement:")
            .context("Python package name missing")?;
        let name = validated_pypi_name(name)?;
        let version = instance
            .resolved_version
            .as_deref()
            .context("Python lock version missing")?;
        let response = http.get(&format!(
            "https://pypi.org/pypi/{name}/{}/json",
            crate::sources::encode(version)
        ))?;
        let metadata: PypiResponse = response.json()?;
        validate_pypi_info(&metadata.info, &name, Some(version))?;
        if !metadata.urls.iter().any(|file| {
            lock.sha256
                .iter()
                .any(|hash| hash.eq_ignore_ascii_case(&file.digests.sha256))
        }) {
            bail!("PyPI release has no SHA-256 matching the lock; package identity unverified");
        }
        let evidence = http.store.record_evidence(
            &response.body,
            "registry_hash_match",
            Some(response.url),
            EvidenceKind::Identity,
        )?;
        let purl = packageurl::PackageUrl::new("pypi", &name)?.to_string();
        instance.reference = purl.clone();
        instance.purl = Some(purl);
        instance.identity_evidence.push(evidence);
        return Ok(());
    }
    if instance.has_unverified_local_identity() {
        instance.purl = None;
        instance.upstream = None;
        bail!(
            "local package source is unverified; identify the public package explicitly before external lookup"
        );
    }
    if instance.reference.starts_with("pkg:") {
        let purl: packageurl::PackageUrl<'_> = instance.reference.parse()?;
        instance.purl = Some(purl.to_string());
        if instance.origin == crate::model::Origin::Locked {
            return Ok(());
        }
        let dynamic = instance.requested_version.as_deref() == Some("latest");
        let name = match purl.namespace() {
            Some(namespace) => format!("{namespace}/{}", purl.name()),
            None => purl.name().into(),
        };
        let encoded = crate::sources::encode(&name);
        let requested = instance.requested_version.as_deref();
        let response = match purl.ty() {
            "cargo" => {
                if dynamic {
                    http.get(&format!("https://crates.io/api/v1/crates/{encoded}"))?
                } else {
                    if !name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        bail!("invalid crate name");
                    }
                    let lowercase = name.to_ascii_lowercase();
                    let prefix = match lowercase.len() {
                        1 => "1".into(),
                        2 => "2".into(),
                        3 => format!("3/{}", &lowercase[..1]),
                        _ => format!("{}/{}", &lowercase[..2], &lowercase[2..4]),
                    };
                    http.get(&format!("https://index.crates.io/{prefix}/{lowercase}"))?
                }
            }
            "npm" => http.get(&format!(
                "https://registry.npmjs.org/{encoded}/{}",
                crate::sources::encode(requested.unwrap_or("latest"))
            ))?,
            "pypi" => {
                if purl.namespace().is_some() {
                    bail!("PyPI package namespace is unsupported");
                }
                let name = validated_pypi_name(&name)?;
                let path = if dynamic || requested.is_none() {
                    format!("https://pypi.org/pypi/{name}/json")
                } else {
                    format!(
                        "https://pypi.org/pypi/{name}/{}/json",
                        crate::sources::encode(requested.unwrap_or_default())
                    )
                };
                http.get(&path)?
            }
            "composer" => http.get(&format!("https://repo.packagist.org/p2/{name}.json"))?,
            _ => bail!("registry identity/latest resolver unsupported for this ecosystem"),
        };
        let (version, upstream): (Option<String>, Option<String>) = match purl.ty() {
            "cargo" if dynamic => {
                let metadata: CrateResponse = response.json()?;
                (
                    Some(metadata.package.max_stable_version),
                    metadata.package.repository,
                )
            }
            "cargo" => {
                let text = std::str::from_utf8(&response.body)?;
                let mut found = requested.is_none();
                for line in text.lines() {
                    let version: SparseCrateVersion = serde_json::from_str(line)?;
                    if version.name.eq_ignore_ascii_case(&name) && requested == Some(&version.vers)
                    {
                        found = true;
                        if version.yanked {
                            bail!("requested crate version is yanked; inspect registry evidence");
                        }
                    }
                }
                if !found {
                    bail!("requested version not present in authoritative crate index");
                }
                (requested.map(str::to_owned), None)
            }
            "npm" => {
                let metadata: NpmVersion = response.json()?;
                if metadata.name != name
                    || (!dynamic && requested.is_some_and(|version| version != metadata.version))
                {
                    bail!("npm identity/version mismatch");
                }
                let repository = metadata.repository.map(|repository| match repository {
                    RepositoryMetadata::Url(url) | RepositoryMetadata::Object { url } => url,
                });
                (
                    if requested.is_some() {
                        Some(metadata.version)
                    } else {
                        None
                    },
                    repository,
                )
            }
            "pypi" => {
                let metadata: PypiResponse = response.json()?;
                validate_pypi_info(&metadata.info, &name, requested.filter(|_| !dynamic))?;
                (requested.map(|_| metadata.info.version), None)
            }
            "composer" => {
                let metadata: ComposerMetadata = response.json()?;
                let versions = metadata
                    .packages
                    .get(&name)
                    .context("package missing from registry")?;
                if !dynamic {
                    let matching = versions.iter().find(|version| {
                        requested.is_none()
                            || Some(version.version.trim_start_matches('v')) == requested
                    });
                    let version =
                        matching.context("requested Composer version missing from registry")?;
                    (
                        requested.map(str::to_owned),
                        version.source.as_ref().map(|source| source.url.clone()),
                    )
                } else {
                    let mut stable: Vec<(&ComposerVersion, semver::Version)> = Vec::new();
                    for version in versions {
                        if let Ok(parsed) = normalized_version(&version.version)
                            && parsed.pre.is_empty()
                        {
                            stable.push((version, parsed));
                        }
                    }
                    stable.sort_by(|a, b| a.1.cmp(&b.1));
                    let (version, _) = stable.last().context("no stable Composer version")?;
                    (
                        Some(version.version.clone()),
                        version.source.as_ref().map(|source| source.url.clone()),
                    )
                }
            }
            _ => bail!("unsupported registry"),
        };
        if dynamic
            && version.as_deref().is_none_or(|version| {
                if purl.ty() == "pypi" {
                    version
                        .parse::<pep508_rs::pep440_rs::Version>()
                        .map_or(true, |version| !version.is_stable())
                } else {
                    normalized_version(version).map_or(true, |version| !version.pre.is_empty())
                }
            })
        {
            bail!("registry did not resolve a stable version");
        }
        instance.resolved_version = version;
        if instance.upstream.is_none() {
            instance.upstream = upstream.and_then(clean_repository);
        }
        instance.identity_evidence.push(http.store.record_evidence(
            &response.body,
            "registry",
            Some(response.url),
            EvidenceKind::Identity,
        )?);
        return Ok(());
    }
    let (repository, cpe, latest_url) = match instance.reference.as_str() {
        "keycloak" => (
            "https://github.com/keycloak/keycloak",
            "cpe:2.3:a:redhat:keycloak",
            "https://api.github.com/repos/keycloak/keycloak/releases/latest",
        ),
        "wordpress" => (
            "https://github.com/WordPress/WordPress",
            "cpe:2.3:a:wordpress:wordpress",
            "https://api.wordpress.org/core/version-check/1.7/",
        ),
        "php" => (
            "https://github.com/php/php-src",
            "cpe:2.3:a:php:php",
            "https://www.php.net/releases/?json&max=1",
        ),
        _ => {
            if let Some(upstream) = &instance.upstream {
                crate::profile::public_https_syntax(upstream)?;
                return Ok(());
            }
            bail!("ambiguous_identity: unknown alias; provide a verified public upstream or PURL");
        }
    };
    if instance.upstream.is_none() {
        instance.upstream = Some(repository.into());
    }
    instance.cpe_product = Some(cpe.into());
    let mapping = format!("builtin-v1:{}:{repository}:{cpe}", instance.reference);
    instance.identity_evidence.push(http.store.record_evidence(
        mapping.as_bytes(),
        "documented_product_mapping",
        Some(repository.into()),
        EvidenceKind::Identity,
    )?);
    if instance.requested_version.as_deref() != Some("latest") {
        return Ok(());
    }
    let response = http.get(latest_url)?;
    let version = match instance.reference.as_str() {
        "keycloak" => {
            let release: Release = response.json()?;
            if release.draft || release.prerelease {
                bail!("release is not stable");
            }
            release.tag_name.trim_start_matches('v').to_owned()
        }
        "wordpress" => {
            let releases: Wordpress = response.json()?;
            releases
                .offers
                .into_iter()
                .find(|offer| offer.response == "upgrade")
                .context("stable offer missing")?
                .version
        }
        "php" => {
            let releases: std::collections::BTreeMap<String, PhpRelease> = response.json()?;
            let mut stable: Vec<semver::Version> = Vec::new();
            for release in releases.values() {
                if let Ok(version) = normalized_version(&release.version)
                    && version.pre.is_empty()
                {
                    stable.push(version);
                }
            }
            stable
                .into_iter()
                .max()
                .context("no stable PHP release")?
                .to_string()
        }
        _ => bail!("no product resolver"),
    };
    normalized_version(&version)?;
    instance.resolved_version = Some(version);
    instance.identity_evidence.push(http.store.record_evidence(
        &response.body,
        "vendor_release",
        Some(response.url),
        EvidenceKind::Identity,
    )?);
    Ok(())
}
pub fn clean_repository(value: String) -> Option<String> {
    canonical_repository(&value)
}

/// Forge links (clone, tree, issues) collapse to `https://host/owner/repo` so one project is one
/// research target; values with unresolved build placeholders such as `${project.scm.tag}` are
/// rejected because they name no real page.
pub fn canonical_repository(value: &str) -> Option<String> {
    if value.contains("${") {
        return None;
    }
    let value = value.trim().trim_start_matches("git+");
    let mut url = crate::profile::public_https_syntax(value).ok()?;
    let segments: Vec<String> = url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let project: Option<Vec<&str>> = match url.host_str() {
        Some("github.com" | "bitbucket.org") => {
            Some(segments.iter().take(2).map(String::as_str).collect())
        }
        Some(host) if host == "gitlab.com" || host.starts_with("gitlab.") => {
            let mut project: Vec<&str> = segments
                .iter()
                .take_while(|segment| segment.as_str() != "-")
                .map(String::as_str)
                .collect();
            // Legacy GitLab routes without the `/-/` separator.
            if project.len() > 2 && matches!(project.last(), Some(&("issues" | "merge_requests"))) {
                project.pop();
            }
            Some(project)
        }
        _ => None,
    };
    if let Some(project) = project {
        if project.len() < 2 {
            return None;
        }
        let path = format!("/{}", project.join("/"));
        url.set_path(path.trim_end_matches(".git"));
        url.set_query(None);
        url.set_fragment(None);
    }
    Some(
        url.as_str()
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .to_owned(),
    )
}

pub(crate) fn normalize_pypi(name: &str) -> String {
    let mut result = String::new();
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !result.ends_with('-') {
                result.push('-');
            }
        } else {
            result.push(character.to_ascii_lowercase());
        }
    }
    result
}

fn validated_pypi_name(name: &str) -> Result<String> {
    let name = normalize_pypi(name);
    if name.is_empty()
        || name.len() > 200
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        bail!("invalid PyPI package name");
    }
    Ok(name)
}

fn validate_pypi_info(info: &PypiInfo, name: &str, requested: Option<&str>) -> Result<()> {
    if normalize_pypi(&info.name) != normalize_pypi(name) {
        bail!("PyPI package identity mismatch");
    }
    let version: pep508_rs::pep440_rs::Version = info.version.parse()?;
    if let Some(requested) = requested {
        let expected: pep508_rs::pep440_rs::Version = requested.parse()?;
        if expected != version {
            bail!("PyPI package version mismatch");
        }
    }
    Ok(())
}

#[cfg(test)]
mod pypi_tests {
    use super::resolve;
    use crate::{
        model::{Instance, Origin, PythonLock},
        network::Http,
        profile::Component,
        store::Store,
    };

    #[test]
    fn pypi_lock_identity_requires_consent_and_a_matching_registry_hash() {
        let project = uuid::Uuid::new_v4().to_string();
        let store = Store::open(&project).unwrap();
        let hash = "a".repeat(64);
        let url = "https://pypi.org/pypi/foo-bar/1.2/json";
        let key = crate::digest(format!("GET:{url}:").as_bytes());
        let response = serde_json::json!({"info":{"name":"Foo_Bar","version":"1.2"},"urls":[{"digests":{"sha256":hash}}]});
        store
            .connection
            .execute(
                "INSERT INTO cache VALUES (?1,?2,NULL,?3)",
                rusqlite::params![
                    key,
                    serde_json::to_vec(&response).unwrap(),
                    chrono::Utc::now().timestamp()
                ],
            )
            .unwrap();
        let mut instance = Instance::declared(&Component {
            reference: "python-requirement:foo-bar".into(),
            version: Some("1.2".into()),
            usage: Default::default(),
            upstream: None,
            feeds: vec![],
        });
        instance.origin = Origin::Locked;
        instance.python_lock = Some(PythonLock {
            sha256: vec!["a".repeat(64)],
            source_eligible: true,
            via: vec![],
            via_complete: false,
            direct_source: None,
        });
        let mut http = Http::new(&store, true);
        assert_ne!(
            resolve(&mut instance, &mut http, false)[0].state,
            crate::model::CoverageState::Checked
        );
        assert_eq!(http.cache_hits, 0);
        assert_eq!(instance.purl, None);
        let mut wrong_hash = instance.clone();
        wrong_hash.python_lock.as_mut().unwrap().sha256 = vec!["b".repeat(64)];
        assert_ne!(
            resolve(&mut wrong_hash, &mut http, true)[0].state,
            crate::model::CoverageState::Checked
        );
        assert_eq!(wrong_hash.purl, None);
        let mut private = instance.clone();
        private.python_lock.as_mut().unwrap().source_eligible = false;
        let hits = http.cache_hits;
        assert_ne!(
            resolve(&mut private, &mut http, true)[0].state,
            crate::model::CoverageState::Checked
        );
        assert_eq!(http.cache_hits, hits);
        assert_eq!(
            resolve(&mut instance, &mut http, true)[0].state,
            crate::model::CoverageState::Checked
        );
        assert_eq!(instance.purl.as_deref(), Some("pkg:pypi/foo-bar"));
        assert!(
            store
                .evidence_exists(&instance.identity_evidence[0])
                .unwrap()
        );
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }
}
