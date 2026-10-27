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
pub fn resolve(instance: &mut Instance, http: &mut Http<'_>) -> Vec<Coverage> {
    let mut coverage = Vec::new();
    let result = resolve_inner(instance, http);
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
fn resolve_inner(instance: &mut Instance, http: &mut Http<'_>) -> Result<()> {
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
                normalized_version(version).map_or(true, |version| !version.pre.is_empty())
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
