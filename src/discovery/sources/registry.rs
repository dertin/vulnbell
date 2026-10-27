use super::{fingerprint, record_document};
use crate::{
    discovery::contracts::{IdentityObservation, MappingState, SourceKind, SourceMapping},
    model::EvidenceReference,
    network::Http,
    store::Store,
};
use anyhow::{Context, Result};
use rusqlite::params;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const NOT_ACQUIRED: &str =
    "not acquired by native registry mapping; an agent may map it from the repository pages";
pub(super) const NATIVE_RATIONALE: &str = "Native registry mapping";
/// Recorded in native Maven rationales; bump it when POM resolution changes so incomplete
/// mappings from earlier revisions are mapped again.
pub(super) const MAVEN_MAPPER: &str = "Maven effective POM revision 5";
/// Maven inheritance depth followed for `scm`, `issueManagement` and `url`.
const MAX_PARENT_POMS: usize = 5;
/// Bounds nested and self-referencing Maven property definitions.
const MAX_INTERPOLATION_PASSES: usize = 32;
const FORGES_WITH_SSH: [&str; 3] = ["github.com", "gitlab.com", "bitbucket.org"];
const NATIVE_ADVISORIES: &str =
    "advisories are queried natively by scan (OSV, GHSA, RustSec, NVD); no tracker page acquired";
/// POM sections whose `<url>` children do not describe the project itself.
const POM_NESTED: [&str; 18] = [
    "parent",
    "organization",
    "licenses",
    "developers",
    "contributors",
    "scm",
    "issueManagement",
    "ciManagement",
    "mailingLists",
    "distributionManagement",
    "repositories",
    "pluginRepositories",
    "build",
    "profiles",
    "dependencies",
    "dependencyManagement",
    "reporting",
    "properties",
];

#[derive(Debug, Serialize)]
pub struct RegistryFailure {
    #[serde(rename = "ref")]
    pub reference: String,
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct RegistryRun {
    pub mapped_components: usize,
    pub registry_documents: usize,
    /// Pending components whose ecosystem has no native registry mapper.
    pub unsupported_components: usize,
    pub failed: Vec<RegistryFailure>,
    /// True when a registry asked to slow down; the remaining components stay pending.
    pub rate_limited: bool,
}

#[derive(Debug, Default)]
struct Declared {
    repository: Option<String>,
    website: Option<String>,
    documentation: Option<String>,
    issues: Option<String>,
    changelog: Option<String>,
    /// Declared repository whose GitHub page answered HTTP 404.
    missing_repository: Option<String>,
    /// Declared issue tracker on another GitHub repository that answered HTTP 404.
    missing_issues: Option<String>,
}

fn https(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    crate::profile::public_https_syntax(value)
        .is_ok()
        .then(|| value.to_owned())
}

fn text<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

/// npm accepts either `"url"` or `{ "url": "..." }` for repository and bugs.
fn string_or_url<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    let field = value.get(key)?;
    field.as_str().or_else(|| text(field, "url"))
}

/// Content of the first `<tag>` or `<tag attributes>` element.
fn xml_section<'a>(document: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0;
    let start = loop {
        let found = document[from..].find(&open)? + from + open.len();
        match document[found..].chars().next()? {
            '>' => break found + 1,
            character if character.is_whitespace() => {
                break document[found..].find('>')? + found + 1;
            }
            _ => from = found,
        }
    };
    let end = document[start..].find(&close)? + start;
    Some(document[start..end].trim())
}

fn raw(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Direct `<properties>` children of a POM; comments are skipped.
fn pom_properties(pom: &str) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();
    let Some(mut section) = xml_section(pom, "properties") else {
        return properties;
    };
    while let Some(start) = section.find('<') {
        section = &section[start + 1..];
        if let Some(comment) = section.strip_prefix("!--") {
            let Some(end) = comment.find("-->") else {
                break;
            };
            section = &comment[end + 3..];
            continue;
        }
        let Some(name_end) = section.find('>') else {
            break;
        };
        let name = &section[..name_end];
        if name.ends_with('/') {
            section = &section[name_end + 1..];
            continue;
        }
        let close = format!("</{name}>");
        let Some(value_end) = section[name_end + 1..].find(&close) else {
            break;
        };
        let value = &section[name_end + 1..name_end + 1 + value_end];
        properties.insert(name.to_owned(), value.trim().to_owned());
        section = &section[name_end + 1 + value_end + close.len()..];
    }
    properties
}

/// Coordinates `${project.*}` refers to in the effective model of the child POM.
fn project_properties(pom: &str) -> BTreeMap<String, String> {
    let project = strip_sections(pom, &POM_NESTED);
    let parent = xml_section(pom, "parent").unwrap_or_default();
    let mut properties = BTreeMap::new();
    for coordinate in ["groupId", "artifactId", "version"] {
        if let Some(value) =
            xml_section(&project, coordinate).or_else(|| xml_section(parent, coordinate))
        {
            properties.insert(format!("project.{coordinate}"), value.to_owned());
        }
    }
    properties
}

/// Replaces `${name}` from the merged chain properties; an undefined name leaves no URL.
fn interpolate(value: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let mut value = value.to_owned();
    for _ in 0..MAX_INTERPOLATION_PASSES {
        let Some(start) = value.find("${") else {
            return Some(value);
        };
        let end = value[start..].find('}')? + start;
        let replacement = properties.get(&value[start + 2..end])?;
        value.replace_range(start..=end, replacement);
    }
    None
}

fn resolve_pom(urls: PomUrls, properties: &BTreeMap<String, String>) -> Declared {
    let mut properties = properties.clone();
    if let Some(tag) = urls.scm_tag {
        properties
            .entry("project.scm.tag".to_owned())
            .or_insert(tag);
    }
    let resolve = |value: Option<String>| {
        value
            .and_then(|value| interpolate(&value, &properties))
            .and_then(|value| https(Some(&value)))
    };
    let candidates: Vec<String> = urls
        .scm
        .iter()
        .filter_map(|value| interpolate(value, &properties).and_then(|value| scm_https(&value)))
        .collect();
    // Some POMs put the project website in `scm/url` and the repository only in `connection`.
    let on_forge = |url: &&String| {
        url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(|host| FORGES_WITH_SSH.contains(&host)))
            .unwrap_or(false)
    };
    Declared {
        repository: candidates
            .iter()
            .find(on_forge)
            .or(candidates.first())
            .cloned(),
        website: resolve(urls.website),
        documentation: None,
        issues: resolve(urls.issues),
        changelog: None,
        missing_repository: None,
        missing_issues: None,
    }
}

fn strip_sections(document: &str, tags: &[&str]) -> String {
    let mut remaining = document.to_owned();
    for tag in tags {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        while let Some(start) = remaining.find(&open) {
            let Some(end) = remaining[start..].find(&close) else {
                break;
            };
            remaining.replace_range(start..start + end + close.len(), "");
        }
    }
    remaining
}

fn registry_url(reference: &str, version: Option<&str>) -> Option<String> {
    let purl: packageurl::PackageUrl<'_> = reference.parse().ok()?;
    let name = purl.name();
    let encode = crate::sources::encode;
    match (purl.ty(), version) {
        ("cargo", _) => Some(format!("https://crates.io/api/v1/crates/{}", encode(name))),
        ("npm", Some(version)) => {
            let full = match purl.namespace() {
                Some(namespace) => format!("{namespace}/{name}"),
                None => name.to_owned(),
            };
            Some(format!(
                "https://registry.npmjs.org/{}/{}",
                encode(&full),
                encode(version)
            ))
        }
        ("pypi", Some(version)) => Some(format!(
            "https://pypi.org/pypi/{}/{}/json",
            encode(name),
            encode(version)
        )),
        ("maven", Some(version)) => {
            let group = purl.namespace()?.replace('.', "/");
            Some(format!(
                "https://repo1.maven.org/maven2/{group}/{name}/{version}/{name}-{version}.pom"
            ))
        }
        _ => None,
    }
}

/// `pkg:maven/groupId/artifactId` of the project a POM builds; `groupId` may come from `<parent>`.
pub(super) fn maven_reference(pom: &str) -> Option<String> {
    let coordinates = project_properties(pom);
    let group = coordinates.get("project.groupId")?;
    let artifact = coordinates.get("project.artifactId")?;
    let literal = |value: &str| !value.is_empty() && !value.contains(['$', '/', '<', ' ']);
    (literal(group) && literal(artifact)).then(|| format!("pkg:maven/{group}/{artifact}"))
}

/// Maven Central URL of the literal `<parent>` coordinates; property placeholders are not resolved.
fn parent_pom_url(pom: &str) -> Option<String> {
    let parent = xml_section(pom, "parent")?;
    let coordinate = |tag: &str| {
        xml_section(parent, tag).filter(|value| {
            !value.is_empty()
                && !value.contains(['$', '/', '<'])
                && !value.contains(char::is_whitespace)
        })
    };
    let reference = format!(
        "pkg:maven/{}/{}",
        coordinate("groupId")?,
        coordinate("artifactId")?
    );
    registry_url(&reference, Some(coordinate("version")?))
}

/// URLs a POM declares, before inheritance and property interpolation.
#[derive(Debug, Default, Clone)]
struct PomUrls {
    /// `scm` `url`, `connection` and `developerConnection`, in preference order.
    scm: Vec<String>,
    scm_tag: Option<String>,
    website: Option<String>,
    issues: Option<String>,
}

fn pom_urls(pom: &str) -> PomUrls {
    let project = strip_sections(pom, &POM_NESTED);
    let scm = xml_section(pom, "scm");
    PomUrls {
        scm: ["url", "connection", "developerConnection"]
            .into_iter()
            .filter_map(|tag| raw(scm.and_then(|scm| xml_section(scm, tag))))
            .collect(),
        scm_tag: raw(scm.and_then(|scm| xml_section(scm, "tag"))),
        website: raw(xml_section(&project, "url")),
        issues: raw(
            xml_section(pom, "issueManagement").and_then(|issues| xml_section(issues, "url"))
        ),
    }
}

/// Whether `parent` builds in the same reactor as `child`: same version and related groupId.
/// A literal URL in any other parent (an organisation-wide POM) describes that parent project.
fn reactor_parent(child: &BTreeMap<String, String>, parent: &BTreeMap<String, String>) -> bool {
    let coordinate = |properties: &BTreeMap<String, String>, name: &str| {
        properties.get(&format!("project.{name}")).cloned()
    };
    let (Some(child_group), Some(parent_group)) =
        (coordinate(child, "groupId"), coordinate(parent, "groupId"))
    else {
        return false;
    };
    let related = child_group == parent_group
        || child_group.starts_with(&format!("{parent_group}."))
        || parent_group.starts_with(&format!("{child_group}."));
    related
        && coordinate(child, "version").is_some()
        && coordinate(child, "version") == coordinate(parent, "version")
}

/// Fills sections the child POM leaves undeclared, as Maven inheritance does. Outside the
/// reactor only templated (`${...}`) URLs are inherited, since they are resolved per child.
fn inherit(urls: &mut PomUrls, parent: PomUrls, reactor: bool) {
    let usable = |value: &String| reactor || value.contains("${");
    if urls.scm.is_empty() {
        urls.scm = parent.scm.into_iter().filter(usable).collect();
        if !urls.scm.is_empty() {
            urls.scm_tag = urls.scm_tag.take().or(parent.scm_tag);
        }
    }
    urls.website = urls.website.take().or(parent.website.filter(usable));
    urls.issues = urls.issues.take().or(parent.issues.filter(usable));
}

/// SCM coordinates as an HTTPS URL; SSH and `git://` forms only for forges that serve the same
/// path over HTTPS.
fn scm_https(value: &str) -> Option<String> {
    let value = match value.strip_prefix("scm:") {
        Some(scm) => scm.strip_prefix("git:")?,
        None => value,
    };
    let forge = |rest: &str, separator: char| {
        let (host, path) = rest.split_once(separator)?;
        FORGES_WITH_SSH
            .contains(&host)
            .then(|| format!("https://{host}/{}", path.trim_start_matches('/')))
    };
    let converted = if let Some(rest) = value.strip_prefix("git@") {
        forge(rest, ':')?
    } else if let Some(rest) = value
        .strip_prefix("ssh://git@")
        .or_else(|| value.strip_prefix("git://"))
    {
        forge(rest, '/')?
    } else {
        value.to_owned()
    };
    https(Some(&converted))
}

fn declared(ecosystem: &str, body: &[u8]) -> Result<Declared> {
    if ecosystem == "maven" {
        let pom = std::str::from_utf8(body).context("POM is not UTF-8")?;
        let mut properties = pom_properties(pom);
        properties.extend(project_properties(pom));
        return Ok(resolve_pom(pom_urls(pom), &properties));
    }
    let value: serde_json::Value = serde_json::from_slice(body)?;
    Ok(match ecosystem {
        "cargo" => {
            let package = value
                .get("crate")
                .context("crates.io record has no crate")?;
            Declared {
                repository: https(text(package, "repository")),
                website: https(text(package, "homepage")),
                documentation: https(text(package, "documentation")),
                ..Declared::default()
            }
        }
        "npm" => Declared {
            repository: https(string_or_url(&value, "repository")),
            website: https(text(&value, "homepage")),
            issues: https(string_or_url(&value, "bugs")),
            ..Declared::default()
        },
        _ => {
            let info = value.get("info").context("PyPI record has no info")?;
            let links: BTreeMap<String, &str> = info
                .get("project_urls")
                .and_then(serde_json::Value::as_object)
                .map(|links| {
                    links
                        .iter()
                        .filter_map(|(key, url)| Some((key.to_ascii_lowercase(), url.as_str()?)))
                        .collect()
                })
                .unwrap_or_default();
            let link = |keys: &[&str]| keys.iter().find_map(|key| links.get(*key).copied());
            Declared {
                repository: https(link(&["source", "source code", "repository", "code"])),
                website: https(link(&["homepage", "home"]).or_else(|| text(info, "home_page"))),
                documentation: https(link(&["documentation", "docs"])),
                issues: https(link(&["issues", "bug tracker", "tracker", "issue tracker"])),
                changelog: https(link(&["changelog", "changes", "release notes"])),
                missing_repository: None,
                missing_issues: None,
            }
        }
    })
}

fn mapping(
    kind: SourceKind,
    url: Option<String>,
    evidence: &[EvidenceReference],
    missing: &str,
) -> SourceMapping {
    let state = if url.is_some() {
        MappingState::Mapped
    } else {
        MappingState::Unavailable
    };
    SourceMapping {
        kind,
        state,
        detail: match url {
            Some(_) => "declared by the publisher in the registry record".to_owned(),
            None => missing.to_owned(),
        },
        url,
        evidence: evidence.to_vec(),
    }
}

fn observation(
    instance_id: &str,
    fingerprint: &str,
    record: &str,
    fields: &Declared,
    evidence: &[EvidenceReference],
) -> IdentityObservation {
    let maven = record.ends_with(".pom");
    let undeclared = if maven {
        "not declared in the effective POM (parent chain and properties)"
    } else {
        "not declared in the registry record"
    };
    IdentityObservation {
        instance_id: instance_id.to_owned(),
        fingerprint: fingerprint.to_owned(),
        version: None,
        cpe_product: None,
        rationale: format!(
            "{NATIVE_RATIONALE}{} from {record}{}; publisher-declared metadata, not an independent ownership proof.",
            if maven {
                format!(" ({MAVEN_MAPPER})")
            } else {
                String::new()
            },
            if evidence.len() > 1 {
                format!(" and {} parent POM(s)", evidence.len() - 1)
            } else {
                String::new()
            }
        ),
        sources: vec![
            mapping(
                SourceKind::Website,
                fields.website.clone(),
                evidence,
                undeclared,
            ),
            mapping(
                SourceKind::Repository,
                fields
                    .repository
                    .clone()
                    .and_then(crate::identity::clean_repository),
                evidence,
                &match &fields.missing_repository {
                    Some(url) => format!("declared repository {url} answers HTTP 404"),
                    None => undeclared.to_owned(),
                },
            ),
            mapping(
                SourceKind::Issues,
                fields.issues.clone(),
                evidence,
                &match &fields.missing_issues {
                    Some(url) => format!("declared issue tracker {url} answers HTTP 404"),
                    None => NOT_ACQUIRED.to_owned(),
                },
            ),
            mapping(SourceKind::ProposedChanges, None, evidence, NOT_ACQUIRED),
            mapping(SourceKind::Discussions, None, evidence, NOT_ACQUIRED),
            mapping(
                SourceKind::Documentation,
                fields.documentation.clone(),
                evidence,
                undeclared,
            ),
            mapping(
                SourceKind::Changelog,
                fields.changelog.clone(),
                evidence,
                NOT_ACQUIRED,
            ),
            mapping(
                SourceKind::Releases,
                Some(record.to_owned()),
                evidence,
                undeclared,
            ),
            mapping(SourceKind::Advisories, None, evidence, NATIVE_ADVISORIES),
        ],
    }
}

/// Whether a declared GitHub repository answers HTTP 404 (deleted, renamed without redirect or
/// never public). Other forges answer anonymous probes ambiguously, so they are not probed, and
/// any other failure keeps the declared mapping.
fn github_repository_missing(http: &mut Http<'_>, repository: &str) -> bool {
    let Some(root) = crate::identity::canonical_repository(repository) else {
        return false;
    };
    if !root.starts_with("https://github.com/") {
        return false;
    }
    http.get(&root)
        .err()
        .is_some_and(|error| error.to_string().contains("HTTP 404"))
}

/// Maps pending components from crates.io, npm, PyPI and Maven Central records, one registry
/// request per package, up to `limit` packages.
pub(in crate::discovery) fn map(
    store: &Store,
    scope: &str,
    first_party: &BTreeSet<String>,
    http: &mut Http<'_>,
    limit: usize,
) -> Result<RegistryRun> {
    let mut run = RegistryRun::default();
    let mut packages: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for target in super::targets(
        store,
        scope,
        first_party,
        super::Mapper::Registry,
        usize::MAX,
    )? {
        match registry_url(&target.reference, target.version.as_deref()) {
            Some(url) => packages
                .entry(url)
                .or_default()
                .push((target.instance_id, target.fingerprint)),
            None => run.unsupported_components += 1,
        }
    }
    let snapshot = store.latest()?;
    let mut requests_before_pacing = http.requests;
    for (url, targets) in packages.into_iter().take(limit) {
        let reference = snapshot
            .instances
            .iter()
            .find(|instance| instance.id == targets[0].0)
            .map(|instance| instance.reference.clone())
            .unwrap_or_default();
        let ecosystem = reference
            .parse::<packageurl::PackageUrl<'_>>()
            .map(|purl| purl.ty().to_owned())
            .unwrap_or_default();
        if http.requests != requests_before_pacing {
            // Public registries (crates.io in particular) ask clients for at most one request per second.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        requests_before_pacing = http.requests;
        let response = match http.get(&url) {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();
                if message.contains("source limited") {
                    run.rate_limited = true;
                    break;
                }
                run.failed.push(RegistryFailure {
                    reference,
                    error: message,
                });
                continue;
            }
        };
        let mut fields = match declared(&ecosystem, &response.body) {
            Ok(fields) => fields,
            Err(error) => {
                run.failed.push(RegistryFailure {
                    reference,
                    error: error.to_string(),
                });
                continue;
            }
        };
        let document = record_document(store, &response.url, &response.body)?;
        run.registry_documents += 1;
        let mut evidence = vec![EvidenceReference {
            id: document.id.clone(),
            sha256: document.sha256.clone(),
        }];
        if ecosystem == "maven" {
            let mut pom = String::from_utf8_lossy(&response.body).into_owned();
            let mut urls = pom_urls(&pom);
            let mut properties = pom_properties(&pom);
            let coordinates = project_properties(&pom);
            properties.extend(coordinates.clone());
            for _ in 0..MAX_PARENT_POMS {
                let effective = resolve_pom(urls.clone(), &properties);
                if effective.repository.is_some() && effective.issues.is_some() {
                    break;
                }
                let Some(parent_url) = parent_pom_url(&pom) else {
                    break;
                };
                if http.requests != requests_before_pacing {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                requests_before_pacing = http.requests;
                let parent = match http.get(&parent_url) {
                    Ok(parent) => parent,
                    Err(error) => {
                        run.rate_limited |= error.to_string().contains("source limited");
                        break;
                    }
                };
                let Ok(parent_pom) = std::str::from_utf8(&parent.body) else {
                    break;
                };
                let document = record_document(store, &parent.url, &parent.body)?;
                run.registry_documents += 1;
                evidence.push(EvidenceReference {
                    id: document.id.clone(),
                    sha256: document.sha256.clone(),
                });
                inherit(
                    &mut urls,
                    pom_urls(parent_pom),
                    reactor_parent(&coordinates, &project_properties(parent_pom)),
                );
                for (name, value) in pom_properties(parent_pom) {
                    properties.entry(name).or_insert(value);
                }
                pom = parent_pom.to_owned();
            }
            fields = resolve_pom(urls, &properties);
            if run.rate_limited {
                break;
            }
        }
        if fields
            .repository
            .as_deref()
            .is_some_and(|repository| github_repository_missing(http, repository))
        {
            let root = fields
                .repository
                .as_deref()
                .and_then(crate::identity::canonical_repository);
            let same_root = |url: &Option<String>| {
                url.as_deref()
                    .and_then(crate::identity::canonical_repository)
                    == root
            };
            if same_root(&fields.issues) {
                fields.issues = None;
            }
            if same_root(&fields.website) {
                fields.website = None;
            }
            fields.missing_repository = fields.repository.take();
        }
        let root = |url: Option<&str>| url.and_then(crate::identity::canonical_repository);
        if let Some(issues) = fields.issues.clone()
            && root(Some(&issues)) != root(fields.repository.as_deref())
            && github_repository_missing(http, &issues)
        {
            fields.missing_issues = Some(issues);
            fields.issues = None;
        }
        for (instance_id, current) in targets {
            let Some(instance) = snapshot
                .instances
                .iter()
                .find(|instance| instance.id == instance_id)
            else {
                continue;
            };
            if fingerprint(instance) != current {
                continue;
            }
            let observation =
                observation(&instance_id, &current, &response.url, &fields, &evidence);
            let body = serde_json::to_string(&observation)?;
            store.connection.execute(
                "INSERT INTO discovery_history(scope,phase,body,recorded_at) VALUES (?1,'sources-native',?2,?3)",
                params![scope, body, crate::now()],
            )?;
            store.connection.execute(
                "INSERT OR REPLACE INTO discovery_sources VALUES (?1,?2,?3,?4,?5)",
                params![scope, instance_id, current, crate::now(), body],
            )?;
            run.mapped_components += 1;
        }
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pom_project_url_ignores_nested_sections_and_scm_maps_the_repository() {
        let pom = br#"<project><parent><url>https://parent.example/</url></parent>
<url>https://www.keycloak.org</url><licenses><license><url>https://license.example/</url></license></licenses>
<scm><url>https://github.com/keycloak/keycloak</url></scm>
<issueManagement><url>https://github.com/keycloak/keycloak/issues</url></issueManagement></project>"#;
        let fields = declared("maven", pom).unwrap();
        assert_eq!(fields.website.as_deref(), Some("https://www.keycloak.org"));
        assert_eq!(
            fields.repository.as_deref(),
            Some("https://github.com/keycloak/keycloak")
        );
        assert_eq!(
            fields.issues.as_deref(),
            Some("https://github.com/keycloak/keycloak/issues")
        );
    }

    #[test]
    fn forge_links_collapse_to_one_repository_and_placeholders_are_rejected() {
        let canonical = crate::identity::canonical_repository;
        for link in [
            "https://github.com/apache/maven-compiler-plugin/issues",
            "git+https://github.com/apache/maven-compiler-plugin.git",
            "https://github.com/apache/maven-compiler-plugin/tree/main",
        ] {
            assert_eq!(
                canonical(link).as_deref(),
                Some("https://github.com/apache/maven-compiler-plugin")
            );
        }
        assert_eq!(
            canonical("https://gitlab.com/group/sub/project/-/issues").as_deref(),
            Some("https://gitlab.com/group/sub/project")
        );
        assert!(
            canonical("https://github.com/apache/maven-jar-plugin/tree/${project.scm.tag}")
                .is_none()
        );
        for link in [
            "https://gitlab.ow2.org/asm/asm/issues",
            "https://gitlab.ow2.org/asm/asm/-/merge_requests",
        ] {
            assert_eq!(
                canonical(link).as_deref(),
                Some("https://gitlab.ow2.org/asm/asm")
            );
        }
        assert!(canonical("https://github.com/apache").is_none());
        assert_eq!(
            canonical("https://issues.apache.org/jira/browse/FREEMARKER").as_deref(),
            Some("https://issues.apache.org/jira/browse/FREEMARKER")
        );
    }

    #[test]
    fn maven_parent_poms_supply_undeclared_scm_and_placeholders_stop_the_chain() {
        let child = "<project><parent><groupId>io.quarkus</groupId><artifactId>quarkus-extensions-parent</artifactId><version>3.40.1</version></parent><artifactId>quarkus-agroal</artifactId></project>";
        assert_eq!(
            parent_pom_url(child).as_deref(),
            Some(
                "https://repo1.maven.org/maven2/io/quarkus/quarkus-extensions-parent/3.40.1/quarkus-extensions-parent-3.40.1.pom"
            )
        );
        assert!(
            parent_pom_url("<project><parent><groupId>a</groupId><artifactId>b</artifactId><version>${revision}</version></parent></project>")
                .is_none()
        );
        let none = BTreeMap::new();
        let mut urls = pom_urls(child);
        inherit(
            &mut urls,
            pom_urls(
                "<project><url>https://quarkus.io</url><scm><url>https://github.com/quarkusio/quarkus</url></scm></project>",
            ),
            true,
        );
        let fields = resolve_pom(urls, &none);
        assert_eq!(
            fields.repository.as_deref(),
            Some("https://github.com/quarkusio/quarkus")
        );
        assert_eq!(fields.website.as_deref(), Some("https://quarkus.io"));
        let mut own =
            pom_urls("<project><scm><url>https://github.com/own/repo</url></scm></project>");
        inherit(
            &mut own,
            pom_urls("<project><scm><url>https://github.com/parent/repo</url></scm></project>"),
            true,
        );
        assert_eq!(
            resolve_pom(own, &none).repository.as_deref(),
            Some("https://github.com/own/repo")
        );
    }

    #[test]
    fn scm_coordinates_map_to_https_only_where_the_forge_serves_the_same_path() {
        assert_eq!(
            scm_https("git@github.com:open-telemetry/opentelemetry-java.git").as_deref(),
            Some("https://github.com/open-telemetry/opentelemetry-java.git")
        );
        assert_eq!(
            scm_https("scm:git:git://github.com/HdrHistogram/HdrHistogram.git").as_deref(),
            Some("https://github.com/HdrHistogram/HdrHistogram.git")
        );
        assert_eq!(
            scm_https("scm:git:ssh://git@gitlab.com/group/project.git").as_deref(),
            Some("https://gitlab.com/group/project.git")
        );
        assert!(scm_https("git@git.example.internal:team/repo.git").is_none());
        assert!(scm_https("scm:svn:https://svn.apache.org/repos/asf/commons").is_none());
        let pom = "<project><scm><url>https://github.com/apache/httpcomponents-client/tree/${project.scm.tag}</url><connection>scm:git:https://git-wip-us.apache.org/repos/asf/httpcomponents-client.git</connection><tag>4.5.14</tag></scm></project>";
        assert_eq!(
            resolve_pom(pom_urls(pom), &BTreeMap::new())
                .repository
                .as_deref(),
            Some("https://github.com/apache/httpcomponents-client/tree/4.5.14")
        );
        let website_in_url = "<project><scm><connection>scm:git:git://github.com/aeshell/aesh.git</connection><url>https://aeshell.github.io/</url></scm></project>";
        assert_eq!(
            resolve_pom(pom_urls(website_in_url), &BTreeMap::new())
                .repository
                .as_deref(),
            Some("https://github.com/aeshell/aesh.git")
        );
        let ssh_only =
            "<project><scm><url>git@github.com:vert-x3/vertx-parent.git</url></scm></project>";
        assert_eq!(
            resolve_pom(pom_urls(ssh_only), &BTreeMap::new())
                .repository
                .as_deref(),
            Some("https://github.com/vert-x3/vertx-parent.git")
        );
    }

    #[test]
    fn inherited_pom_urls_use_merged_properties_and_attribute_sections() {
        let child = "<project><parent><groupId>org.apache.commons</groupId><artifactId>commons-parent</artifactId><version>98</version></parent><artifactId>commons-io</artifactId><version>2.22.0</version><properties><!-- ids --><commons.componentid>io</commons.componentid><commons.jira.id>IO</commons.jira.id><empty/></properties></project>";
        let parent = "<project><properties><commons.repo.name>commons-${commons.componentid}</commons.repo.name><commons.jira.id>PARENT</commons.jira.id></properties><scm child.scm.url.inherit.append.path=\"false\"><url>https://gitbox.apache.org/repos/asf?p=${commons.repo.name}.git</url></scm><issueManagement><url>https://issues.apache.org/jira/browse/${commons.jira.id}</url></issueManagement><ciManagement><url>https://github.com/apache/${undefined.name}/actions</url></ciManagement></project>";
        let mut properties = pom_properties(child);
        properties.extend(project_properties(child));
        assert_eq!(
            properties.get("project.artifactId").map(String::as_str),
            Some("commons-io")
        );
        for (name, value) in pom_properties(parent) {
            properties.entry(name).or_insert(value);
        }
        let mut urls = pom_urls(child);
        inherit(&mut urls, pom_urls(parent), false);
        let resolved = resolve_pom(urls, &properties);
        assert_eq!(
            resolved.repository.as_deref(),
            Some("https://gitbox.apache.org/repos/asf?p=commons-io.git")
        );
        assert_eq!(
            resolved.issues.as_deref(),
            Some("https://issues.apache.org/jira/browse/IO")
        );
        assert_eq!(
            interpolate("https://github.com/apache/${undefined.name}", &properties),
            None
        );
        let recursive = BTreeMap::from([("a".to_owned(), "${a}".to_owned())]);
        assert_eq!(interpolate("${a}", &recursive), None);
    }

    #[test]
    fn organisation_parents_do_not_lend_their_own_literal_urls() {
        let child = "<project><parent><groupId>org.jboss</groupId><artifactId>jboss-parent</artifactId><version>49</version></parent><groupId>org.wildfly.common</groupId><artifactId>wildfly-common</artifactId><version>1.5.4.Final</version></project>";
        let parent = "<project><groupId>org.jboss</groupId><artifactId>jboss-parent</artifactId><version>49</version><url>https://www.jboss.org</url><scm><url>https://github.com/jboss/jboss-parent-pom</url></scm><issueManagement><url>https://issues.redhat.com/</url></issueManagement></project>";
        let coordinates = project_properties(child);
        let reactor = reactor_parent(&coordinates, &project_properties(parent));
        assert!(!reactor);
        let mut urls = pom_urls(child);
        inherit(&mut urls, pom_urls(parent), reactor);
        let resolved = resolve_pom(urls, &coordinates);
        assert_eq!(
            (resolved.repository, resolved.website, resolved.issues),
            (None, None, None)
        );
        let module = "<project><parent><groupId>com.fasterxml.jackson.jakarta.rs</groupId><artifactId>jackson-jakarta-rs-providers</artifactId><version>2.21.7</version></parent><artifactId>jackson-jakarta-rs-base</artifactId></project>";
        let reactor_pom = "<project><groupId>com.fasterxml.jackson.jakarta.rs</groupId><artifactId>jackson-jakarta-rs-providers</artifactId><version>2.21.7</version></project>";
        assert!(reactor_parent(
            &project_properties(module),
            &project_properties(reactor_pom)
        ));
    }

    #[test]
    fn registry_urls_are_exact_per_ecosystem() {
        assert_eq!(
            registry_url("pkg:maven/org.keycloak/keycloak-core", Some("26.8.1")).as_deref(),
            Some(
                "https://repo1.maven.org/maven2/org/keycloak/keycloak-core/26.8.1/keycloak-core-26.8.1.pom"
            )
        );
        assert_eq!(
            registry_url("pkg:pypi/requests", Some("2.31.0")).as_deref(),
            Some("https://pypi.org/pypi/requests/2.31.0/json")
        );
        assert!(registry_url("pkg:pypi/requests", None).is_none());
        assert!(registry_url("pkg:golang/example.com/x", Some("1.0.0")).is_none());
    }
}
