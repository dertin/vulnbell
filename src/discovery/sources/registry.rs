use super::{fingerprint, record_document};
use crate::{
    discovery::contracts::{IdentityObservation, MappingState, SourceKind, SourceMapping},
    model::EvidenceReference,
    network::Http,
    store::Store,
};
use anyhow::{Context, Result, bail};
use rusqlite::params;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const NOT_ACQUIRED: &str =
    "not acquired by native registry mapping; an agent may map it from the repository pages";
pub(super) const NATIVE_RATIONALE: &str = "Native registry mapping";
/// Identifies the POM mapping rules recorded with each source observation.
pub(super) const MAVEN_MAPPER: &str = "Maven effective POM revision 6";
/// Maven inheritance depth followed for `scm`, `issueManagement` and `url`.
const MAX_PARENT_POMS: usize = 5;
/// Bounds nested and self-referencing Maven property definitions.
const MAX_INTERPOLATION_PASSES: usize = 32;
const FORGES_WITH_SSH: [&str; 3] = ["github.com", "gitlab.com", "bitbucket.org"];
const NATIVE_ADVISORIES: &str =
    "advisories are queried natively by scan (OSV, GHSA, RustSec, NVD); no tracker page acquired";
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

const MAX_POM_BYTES: usize = 8 * 1024 * 1024;
const MAX_POM_NODES: u32 = 100_000;

#[derive(Default)]
struct ParsedPom {
    urls: PomUrls,
    properties: BTreeMap<String, String>,
    coordinates: BTreeMap<String, String>,
    parent: PomParent,
}

#[derive(Default)]
enum PomParent {
    #[default]
    None,
    Registry(String),
    Unresolved,
}

fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Result<Option<roxmltree::Node<'a, 'input>>> {
    let mut matches = node.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == node.tag_name().namespace()
            && child.tag_name().name() == name
    });
    let first = matches.next();
    if matches.next().is_some() {
        bail!("duplicate Maven field {name}");
    }
    Ok(first)
}

fn scalar(node: roxmltree::Node<'_, '_>) -> Result<Option<String>> {
    if node.children().any(|child| child.is_element()) {
        bail!("Maven field must contain text only");
    }
    let text = node
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<String>();
    let value = text.trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

fn field(node: roxmltree::Node<'_, '_>, name: &str) -> Result<Option<String>> {
    child(node, name)?
        .map(scalar)
        .transpose()
        .map(Option::flatten)
}

fn parse_pom(pom: &str) -> Result<ParsedPom> {
    if pom.len() > MAX_POM_BYTES || pom.contains("<!DOCTYPE") {
        bail!("POM exceeds limits or declares a DTD");
    }
    let document = roxmltree::Document::parse_with_options(
        pom,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_POM_NODES,
            entity_resolver: None,
        },
    )
    .context("invalid Maven POM")?;
    let project = document.root_element();
    if project.tag_name().name() != "project"
        || !matches!(
            project.tag_name().namespace(),
            None | Some("http://maven.apache.org/POM/4.0.0")
        )
    {
        bail!("Maven POM requires a project root");
    }
    let parent = child(project, "parent")?;
    let parent_field = |name: &str| {
        parent
            .map(|node| field(node, name))
            .transpose()
            .map(Option::flatten)
    };
    let mut coordinates = BTreeMap::new();
    for name in ["groupId", "artifactId", "version"] {
        let mut value = field(project, name)?;
        if value.is_none() && name != "artifactId" {
            value = parent_field(name)?;
        }
        if let Some(value) = value {
            coordinates.insert(format!("project.{name}"), value);
        }
    }
    let mut properties = BTreeMap::new();
    if let Some(section) = child(project, "properties")? {
        for property in section.children().filter(|node| {
            node.is_element() && node.tag_name().namespace() == section.tag_name().namespace()
        }) {
            let name = property.tag_name().name().to_owned();
            let value = scalar(property)?.unwrap_or_default();
            if properties.insert(name, value).is_some() {
                bail!("duplicate Maven property");
            }
        }
    }
    let parent_url = match (
        parent_field("groupId")?,
        parent_field("artifactId")?,
        parent_field("version")?,
    ) {
        (Some(group), Some(artifact), Some(version))
            if [&group, &artifact, &version].iter().all(|value| {
                !value.is_empty()
                    && !value.contains(['$', '/', '<'])
                    && !value.contains(char::is_whitespace)
            }) =>
        {
            registry_url(&format!("pkg:maven/{group}/{artifact}"), Some(&version))
        }
        _ => None,
    };
    let parent = match (parent, parent_url) {
        (None, _) => PomParent::None,
        (Some(_), Some(url)) => PomParent::Registry(url),
        (Some(_), None) => PomParent::Unresolved,
    };
    let scm = child(project, "scm")?;
    let scm_field = |name: &str| {
        scm.map(|node| field(node, name))
            .transpose()
            .map(Option::flatten)
    };
    let mut scm_urls = Vec::new();
    for name in ["url", "connection", "developerConnection"] {
        if let Some(value) = scm_field(name)? {
            scm_urls.push(value);
        }
    }
    let issues = child(project, "issueManagement")?
        .map(|node| field(node, "url"))
        .transpose()?
        .flatten();
    Ok(ParsedPom {
        urls: PomUrls {
            scm: scm_urls,
            scm_tag: scm_field("tag")?,
            website: field(project, "url")?,
            issues,
        },
        properties,
        coordinates,
        parent,
    })
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

/// `pkg:maven/groupId/artifactId` of the project a POM builds.
pub(super) fn maven_reference(pom: &str) -> Option<String> {
    let coordinates = parse_pom(pom).ok()?.coordinates;
    let group = coordinates.get("project.groupId")?;
    let artifact = coordinates.get("project.artifactId")?;
    let literal = |value: &str| !value.is_empty() && !value.contains(['$', '/', '<', ' ']);
    (literal(group) && literal(artifact)).then(|| format!("pkg:maven/{group}/{artifact}"))
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
        let parsed = parse_pom(pom)?;
        let mut properties = parsed.properties;
        properties.extend(parsed.coordinates);
        return Ok(resolve_pom(parsed.urls, &properties));
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
    research: &crate::profile::Research,
    http: &mut Http<'_>,
    limit: usize,
) -> Result<RegistryRun> {
    let mut run = RegistryRun::default();
    let mut packages: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for target in super::targets(
        store,
        scope,
        first_party,
        research,
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
    let mut instances = HashMap::new();
    for instance in &snapshot.instances {
        instances.entry(instance.id.as_str()).or_insert(instance);
    }
    let mut requests_before_pacing = http.requests;
    for (url, targets) in packages.into_iter().take(limit) {
        let reference = instances
            .get(targets[0].0.as_str())
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
            let pom = std::str::from_utf8(&response.body).context("POM is not UTF-8")?;
            let mut parsed = parse_pom(pom)?;
            let mut urls = parsed.urls.clone();
            let mut properties = parsed.properties.clone();
            let coordinates = parsed.coordinates.clone();
            properties.extend(coordinates.clone());
            let mut invalid_parent = None;
            let mut parents_read = 0;
            loop {
                let effective = resolve_pom(urls.clone(), &properties);
                if effective.repository.is_some() && effective.issues.is_some() {
                    break;
                }
                let parent_url = match &parsed.parent {
                    PomParent::None => break,
                    PomParent::Unresolved => {
                        invalid_parent =
                            Some("parent POM coordinates cannot be resolved".to_owned());
                        break;
                    }
                    PomParent::Registry(_) if parents_read == MAX_PARENT_POMS => {
                        invalid_parent =
                            Some("parent POM chain exceeds the traversal limit".to_owned());
                        break;
                    }
                    PomParent::Registry(url) => url,
                };
                if http.requests != requests_before_pacing {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                requests_before_pacing = http.requests;
                let parent = match http.get(parent_url) {
                    Ok(parent) => parent,
                    Err(error) => {
                        let message = error.to_string();
                        run.rate_limited |= message.contains("source limited");
                        invalid_parent = Some(format!("parent POM unavailable: {message}"));
                        break;
                    }
                };
                parents_read += 1;
                let parent_pom = std::str::from_utf8(&parent.body)
                    .context("parent POM is not UTF-8")
                    .and_then(parse_pom);
                let parent_pom = match parent_pom {
                    Ok(parent_pom) => parent_pom,
                    Err(error) => {
                        invalid_parent = Some(error.to_string());
                        break;
                    }
                };
                let document = record_document(store, &parent.url, &parent.body)?;
                run.registry_documents += 1;
                evidence.push(EvidenceReference {
                    id: document.id.clone(),
                    sha256: document.sha256.clone(),
                });
                inherit(
                    &mut urls,
                    parent_pom.urls.clone(),
                    reactor_parent(&coordinates, &parent_pom.coordinates),
                );
                for (name, value) in &parent_pom.properties {
                    properties
                        .entry(name.clone())
                        .or_insert_with(|| value.clone());
                }
                parsed = parent_pom;
            }
            if let Some(error) = invalid_parent {
                run.failed.push(RegistryFailure { reference, error });
                if run.rate_limited {
                    break;
                }
                continue;
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
            let Some(instance) = instances.get(instance_id.as_str()) else {
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
mod tests;
