use crate::{
    model::{Applicability, Case, Claim, Coverage, CoverageState, EvidenceKind, Instance},
    network::Http,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

mod repository;
pub use repository::case_repository_advisory;
use repository::repository_advisories;
pub(crate) use repository::{
    RangeMatch, github_range_match, repository_package_is, repository_package_match,
};
#[cfg(test)]
use repository::{RepositoryAdvisory, github_repository, same_package};

#[derive(Default)]
pub struct Intelligence {
    pub claims: Vec<Claim>,
    pub coverage: Vec<Coverage>,
}
#[derive(Deserialize)]
struct OsvBatch {
    results: Vec<OsvMatches>,
}
#[derive(Deserialize)]
struct OsvMatches {
    #[serde(default)]
    vulns: Vec<OsvId>,
    next_page_token: Option<String>,
}
#[derive(Deserialize)]
struct OsvId {
    id: String,
}
#[derive(Deserialize)]
struct OsvAdvisory {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    withdrawn: Option<String>,
}
#[derive(Deserialize)]
struct Ghsa {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    withdrawn_at: Option<String>,
}
#[derive(Deserialize)]
struct Kev {
    vulnerabilities: Vec<KevEntry>,
}
#[derive(Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    id: String,
}
#[derive(Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total: usize,
    vulnerabilities: Vec<NvdEntry>,
}
#[derive(Deserialize)]
struct NvdEntry {
    cve: NvdCve,
}
#[derive(Deserialize)]
struct NvdCve {
    id: String,
    #[serde(rename = "vulnStatus")]
    status: String,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
}
#[derive(Deserialize)]
struct Description {
    lang: String,
    value: String,
}
#[derive(Deserialize)]
struct NvdConfiguration {
    operator: Option<String>,
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    nodes: Vec<NvdNode>,
}
#[derive(Deserialize)]
struct NvdNode {
    operator: String,
    #[serde(default)]
    negate: bool,
    #[serde(rename = "cpeMatch", default)]
    matches: Vec<CpeMatch>,
}
#[derive(Deserialize)]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    #[serde(rename = "versionStartIncluding")]
    start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    end_excluding: Option<String>,
}
#[derive(Deserialize)]
struct CveRecord {
    #[serde(rename = "cveMetadata")]
    metadata: CveMetadata,
}
#[derive(Deserialize)]
struct CveMetadata {
    #[serde(rename = "cveId")]
    id: String,
    state: String,
}

pub fn scan(
    instances: &[Instance],
    http: &mut Http<'_>,
    research: &crate::profile::Research,
    previous_cases: &[Case],
) -> Intelligence {
    let mut intelligence = Intelligence::default();
    osv(instances, http, &mut intelligence);
    repository_advisories(instances, http, &mut intelligence, research, previous_cases);
    for instance in instances {
        if instance.resolved_version.is_none() {
            intelligence.coverage.push(Coverage::new(
                "advisories",
                &instance.id,
                CoverageState::Unresolved,
                "version required; latest was not sent to vulnerability APIs",
            ));
            continue;
        }
        if instance.purl.is_some() && instance.provenance.direct == Some(true) {
            if let Err(error) = ghsa(instance, http, &mut intelligence) {
                intelligence.coverage.push(Coverage::new(
                    "ghsa",
                    &instance.id,
                    CoverageState::Partial,
                    error.to_string(),
                ));
            }
        } else if instance.purl.is_some() {
            intelligence.coverage.push(Coverage::new(
                "ghsa",
                &instance.id,
                CoverageState::Partial,
                "OSV aggregated GHSA coverage; direct GHSA checks reserved for declared targets",
            ));
        }
        if instance.cpe_product.is_some() {
            if let Err(error) = nvd(instance, http, &mut intelligence) {
                intelligence.coverage.push(Coverage::new(
                    "nvd",
                    &instance.id,
                    CoverageState::Partial,
                    error.to_string(),
                ));
            }
        } else {
            intelligence.coverage.push(Coverage::new(
                "nvd",
                &instance.id,
                CoverageState::Unsupported,
                "no validated CPE mapping; PURL is not a CPE",
            ));
        }
    }
    enrich(&mut intelligence, instances, http);
    intelligence
}
fn osv(instances: &[Instance], http: &mut Http<'_>, intelligence: &mut Intelligence) {
    let mut unique: BTreeMap<(String, String), Vec<&Instance>> = BTreeMap::new();
    for instance in instances {
        match (&instance.purl, &instance.resolved_version) {
            (Some(purl), Some(version)) => {
                unique
                    .entry((purl.clone(), version.clone()))
                    .or_default()
                    .push(instance);
            }
            _ => intelligence.coverage.push(Coverage::new(
                "osv",
                &instance.id,
                CoverageState::Unsupported,
                "requires supported package identity and exact version; upstream-only is not SCA",
            )),
        }
    }
    let targets: Vec<_> = unique.into_iter().collect();
    for chunk in targets.chunks(100) {
        let queries: Vec<serde_json::Value> = chunk.iter().map(|((purl,version),_)| serde_json::json!({"package":{"purl":purl},"version":version})).collect();
        let result = http
            .post(
                "https://api.osv.dev/v1/querybatch",
                &serde_json::json!({"queries":queries}),
            )
            .and_then(|response| response.json::<OsvBatch>());
        let batch = match result {
            Ok(batch) if batch.results.len() == chunk.len() => batch,
            result => {
                let detail = match result {
                    Err(error) => error.to_string(),
                    Ok(_) => "OSV result count mismatch".into(),
                };
                for (_, instances) in chunk {
                    for instance in instances {
                        intelligence.coverage.push(Coverage::new(
                            "osv",
                            &instance.id,
                            CoverageState::Partial,
                            &detail,
                        ));
                    }
                }
                continue;
            }
        };
        for ((_, instances), matches) in chunk.iter().zip(batch.results) {
            let mut ids: Vec<String> = matches
                .vulns
                .into_iter()
                .map(|vulnerability| vulnerability.id)
                .collect();
            let mut page_token = matches.next_page_token;
            let mut complete = true;
            for _ in 0..20 {
                let Some(token) = page_token.take() else {
                    break;
                };
                let instance = instances[0];
                let result = http.post("https://api.osv.dev/v1/query", &serde_json::json!({"package":{"purl":instance.purl},"version":instance.resolved_version,"page_token":token})).and_then(|response| response.json::<OsvMatches>());
                match result {
                    Ok(page) => {
                        ids.extend(page.vulns.into_iter().map(|vulnerability| vulnerability.id));
                        page_token = page.next_page_token;
                    }
                    Err(_) => {
                        complete = false;
                        break;
                    }
                }
            }
            complete &= page_token.is_none();
            for id in ids {
                let result = http
                    .get(&format!("https://api.osv.dev/v1/vulns/{}", encode(&id)))
                    .and_then(|response| {
                        let advisory: OsvAdvisory = response.json()?;
                        if advisory.withdrawn.is_some() {
                            return Ok(());
                        }
                        let document: serde_json::Value = response.json()?;
                        let evidence = http.store.record_evidence(
                            &response.body,
                            "osv",
                            Some(response.url),
                            EvidenceKind::Advisory,
                        )?;
                        for instance in instances {
                            let applicability = match (&instance.purl, &instance.resolved_version) {
                                (Some(purl), Some(version)) => {
                                    match osv_ranges_match(&document, purl, version) {
                                        Some(true) => Applicability::Affected,
                                        Some(false) => Applicability::NotAffected,
                                        None => Applicability::Unknown,
                                    }
                                }
                                _ => Applicability::Unknown,
                            };
                            if applicability == Applicability::Unknown {
                                complete = false;
                            }
                            let mut evidence = evidence.clone();
                            if applicability == Applicability::NotAffected {
                                evidence.kind = EvidenceKind::NonApplicability;
                            }
                            intelligence.claims.push(Claim {
                                id: advisory.id.clone(),
                                source: "osv".into(),
                                aliases: advisory.aliases.clone(),
                                instance_id: instance.id.clone(),
                                summary: advisory
                                    .summary
                                    .clone()
                                    .unwrap_or_else(|| advisory.id.clone()),
                                applicability,
                                evidence,
                                known_exploited: false,
                            });
                        }
                        Ok(())
                    });
                if result.is_err() {
                    complete = false;
                }
            }
            for instance in instances {
                intelligence.coverage.push(Coverage::new("osv", &instance.id, if complete { CoverageState::Checked } else { CoverageState::Partial }, "exact-version batch query; withdrawn records excluded; indeterminate details or detail/pagination failures reduce coverage"));
            }
        }
    }
}
/// GitHub advisory ecosystem and package name of a PURL; `None` for unsupported ecosystems.
pub(crate) fn github_package(instance: &Instance) -> Result<Option<(&'static str, String)>> {
    let purl: packageurl::PackageUrl<'_> =
        instance.purl.as_deref().context("missing PURL")?.parse()?;
    let ecosystem = match purl.ty() {
        "cargo" => "rust",
        "npm" => "npm",
        "composer" => "composer",
        "pypi" => "pip",
        "golang" => "go",
        "maven" => "maven",
        _ => return Ok(None),
    };
    let name = match purl.namespace() {
        Some(namespace) => format!("{namespace}/{}", purl.name()),
        None => purl.name().into(),
    };
    Ok(Some((ecosystem, name)))
}
fn ghsa(instance: &Instance, http: &mut Http<'_>, intelligence: &mut Intelligence) -> Result<()> {
    let Some((ecosystem, name)) = github_package(instance)? else {
        intelligence.coverage.push(Coverage::new(
            "ghsa",
            &instance.id,
            CoverageState::Unsupported,
            "unsupported ecosystem mapping",
        ));
        return Ok(());
    };
    let name = if ecosystem == "maven" {
        name.replace('/', ":")
    } else {
        name
    };
    let affects = format!(
        "{name}@{}",
        instance
            .resolved_version
            .as_deref()
            .context("missing version")?
    );
    let mut complete = false;
    for page in 1..=10 {
        let url = format!(
            "https://api.github.com/advisories?ecosystem={ecosystem}&affects={}&per_page=100&page={page}",
            encode(&affects)
        );
        let response = http.get(&url)?;
        let advisories: Vec<Ghsa> = response.json()?;
        let length = advisories.len();
        let evidence = http.store.record_evidence(
            &response.body,
            "ghsa",
            Some(url),
            EvidenceKind::Advisory,
        )?;
        for advisory in advisories {
            if advisory.withdrawn_at.is_some() {
                continue;
            }
            intelligence.claims.push(Claim {
                id: advisory.ghsa_id,
                source: "ghsa".into(),
                aliases: advisory.cve_id.into_iter().collect(),
                instance_id: instance.id.clone(),
                summary: advisory.summary,
                applicability: Applicability::Affected,
                evidence: evidence.clone(),
                known_exploited: false,
            });
        }
        if length < 100 && !response.truncated {
            complete = true;
            break;
        }
    }
    intelligence.coverage.push(Coverage::new(
        "ghsa",
        &instance.id,
        if complete {
            CoverageState::Checked
        } else {
            CoverageState::Partial
        },
        "GitHub reviewed advisories filtered by exact package@version; bounded pagination",
    ));
    Ok(())
}

pub fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
/// Evaluate all entries for the package. Unreadable entries prevent exclusion.
pub(crate) fn osv_ranges_match(
    advisory: &serde_json::Value,
    purl: &str,
    version: &str,
) -> Option<bool> {
    let raw_version = version;
    let target: packageurl::PackageUrl<'_> = purl.parse().ok()?;
    let entries = advisory.get("affected")?.as_array()?;
    let mut matched = false;
    let mut unknown = false;
    for entry in entries {
        match osv_package_identity(&entry["package"], Some(purl), Some(raw_version)) {
            Some(true) => {}
            Some(false) => continue,
            None => {
                unknown = true;
                continue;
            }
        }
        matched = true;
        match osv_entry_contains(entry, raw_version, target.ty()) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    if matched && !unknown {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn osv_package_identity(
    package: &serde_json::Value,
    purl: Option<&str>,
    version: Option<&str>,
) -> Option<bool> {
    let target: packageurl::PackageUrl<'_> = purl?.parse().ok()?;
    let entry_purl = package
        .get("purl")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            osv_purl(
                package.get("ecosystem")?.as_str()?,
                package.get("name")?.as_str()?,
            )
        })?;
    let entry: packageurl::PackageUrl<'_> = entry_purl.parse().ok()?;
    let names_match = if entry.ty() == "pypi" && target.ty() == "pypi" {
        normalize_pypi(entry.name()) == normalize_pypi(target.name())
    } else {
        entry.name() == target.name()
    };
    if entry.ty() != target.ty() || entry.namespace() != target.namespace() || !names_match {
        if entry.ty() == target.ty()
            && entry.name().eq_ignore_ascii_case(target.name())
            && entry
                .namespace()
                .unwrap_or("")
                .eq_ignore_ascii_case(target.namespace().unwrap_or(""))
        {
            return None;
        }
        return Some(false);
    }
    if (!entry.qualifiers().is_empty() && entry.qualifiers() != target.qualifiers())
        || (entry.subpath().is_some() && entry.subpath() != target.subpath())
    {
        return None;
    }
    if let Some(entry_version) = entry.version() {
        let target_version = version?;
        if entry_version != target_version
            && crate::identity::normalized_version(entry_version)
                .ok()
                .zip(crate::identity::normalized_version(target_version).ok())
                .is_none_or(|(entry, target)| entry != target)
        {
            return None;
        }
    }
    Some(true)
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

/// Package URL without version for an OSV ecosystem and package name.
pub(crate) fn osv_purl(ecosystem: &str, name: &str) -> Option<String> {
    let purl = match ecosystem {
        "crates.io" => format!("pkg:cargo/{name}"),
        "Maven" => {
            let (group, artifact) = name.split_once(':')?;
            format!("pkg:maven/{group}/{artifact}")
        }
        "npm" => match name.strip_prefix('@') {
            Some(scoped) => format!("pkg:npm/%40{scoped}"),
            None => format!("pkg:npm/{name}"),
        },
        "PyPI" => format!("pkg:pypi/{}", normalize_pypi(name)),
        "Go" => format!("pkg:golang/{name}"),
        "RubyGems" => format!("pkg:gem/{name}"),
        "NuGet" => format!("pkg:nuget/{name}"),
        "Packagist" => format!("pkg:composer/{name}"),
        _ => return None,
    };
    Some(purl)
}

pub(crate) fn precedence_version(value: &str) -> Option<semver::Version> {
    let mut version = crate::identity::normalized_version(value).ok()?;
    version.build = semver::BuildMetadata::EMPTY;
    Some(version)
}

pub(crate) fn ecosystem_version_orderable(ecosystem: &str, value: &str) -> bool {
    match ecosystem.to_ascii_lowercase().as_str() {
        "cargo" | "crates.io" | "rust" | "npm" => semver::Version::parse(value).is_ok(),
        "maven" | "pypi" | "pip" | "go" | "golang" | "rubygems" | "gem" | "nuget" | "packagist"
        | "composer" => {
            let parts: Vec<&str> = value.split('.').collect();
            (2..=3).contains(&parts.len())
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                && crate::identity::normalized_version(value).is_ok()
        }
        _ => false,
    }
}

/// `None` when the entry cannot be evaluated without guessing (Git ranges, unparsable versions,
/// compound GHSA bounds).
pub(crate) fn osv_entry_contains(
    entry: &serde_json::Value,
    raw_version: &str,
    ecosystem: &str,
) -> Option<bool> {
    let exact_listed = entry
        .get("versions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|listed| {
            listed
                .iter()
                .any(|value| value.as_str() == Some(raw_version))
        });
    let Some(version) = crate::identity::normalized_version(raw_version).ok() else {
        return exact_listed.then_some(true);
    };
    let parse = |value: &str| {
        if value == "0" {
            Some(semver::Version::new(0, 0, 0))
        } else {
            crate::identity::normalized_version(value).ok()
        }
    };
    let listed = exact_listed
        || entry
            .get("versions")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|listed| {
                listed
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(parse)
                    .any(|listed| listed == version)
            });
    let Some(ranges) = entry.get("ranges").and_then(serde_json::Value::as_array) else {
        return listed.then_some(true);
    };
    let ghsa_bound = entry
        .pointer("/database_specific/last_known_affected_version_range")
        .and_then(serde_json::Value::as_str);
    if ranges.is_empty() {
        return listed.then_some(true);
    }
    let version = precedence_version(raw_version)?;
    let parse = |value: &str| {
        if value == "0" {
            semver::Version::parse("0.0.0-0").ok()
        } else {
            precedence_version(value)
        }
    };
    let mut unknown = false;
    for range in ranges {
        if !matches!(range.get("type")?.as_str()?, "ECOSYSTEM" | "SEMVER") {
            return None;
        }
        if range["type"] == "ECOSYSTEM" {
            let safe = ecosystem_version_orderable(ecosystem, raw_version)
                && range.get("events")?.as_array()?.iter().all(|event| {
                    event.as_object().is_some_and(|fields| {
                        fields.values().all(|value| {
                            value.as_str().is_some_and(|value| {
                                value == "0" || ecosystem_version_orderable(ecosystem, value)
                            })
                        })
                    })
                })
                && ghsa_bound.is_none_or(|bound| {
                    let value = bound.trim().trim_start_matches(['<', '=']).trim();
                    ecosystem_version_orderable(ecosystem, value)
                });
            if !safe {
                unknown = true;
                continue;
            }
        }
        let mut start: Option<semver::Version> = None;
        let events = range.get("events")?.as_array()?;
        if events.is_empty() {
            return None;
        }
        for event in events {
            let fields = event.as_object()?;
            if fields.len() != 1 {
                return None;
            }
            let (kind, value) = fields.iter().next()?;
            let bound = parse(value.as_str()?)?;
            match kind.as_str() {
                "introduced" => {
                    if start.replace(bound).is_some() {
                        return None;
                    }
                }
                "fixed" | "limit" | "last_affected" => {
                    let begin = start.take()?;
                    if bound < begin {
                        return None;
                    }
                    if begin <= version
                        && (version < bound || kind == "last_affected" && version == bound)
                    {
                        return Some(true);
                    }
                }
                _ => return None,
            }
        }
        if start.is_some_and(|start| start <= version) {
            let Some(bound) = ghsa_bound else {
                return Some(true);
            };
            let bound = bound.trim();
            if bound.contains(',') {
                return None;
            }
            let (inclusive, value) = match bound.strip_prefix("<=") {
                Some(value) => (true, value),
                None => (false, bound.strip_prefix('<')?),
            };
            let upper = parse(value.trim())?;
            if version < upper || inclusive && version == upper {
                return Some(true);
            }
        }
    }
    if listed && unknown {
        Some(true)
    } else if listed || unknown {
        None
    } else {
        Some(false)
    }
}
fn cpe_applies(candidate: &CpeMatch, product: &str, version: &str) -> Result<Option<bool>> {
    if !candidate.vulnerable || !candidate.criteria.starts_with(&format!("{product}:")) {
        return Ok(None);
    }
    let fields: Vec<&str> = candidate.criteria.split(':').collect();
    let exact = fields.get(5).context("invalid CPE")?;
    if *exact != "*" {
        return Ok(Some(*exact == version));
    }
    if version.contains(['-', '+']) {
        bail!("vendor/distro version requires vendor applicability evidence");
    }
    let version = crate::identity::normalized_version(version)?;
    for (bound, inclusive, lower) in [
        (&candidate.start_including, true, true),
        (&candidate.start_excluding, false, true),
        (&candidate.end_including, true, false),
        (&candidate.end_excluding, false, false),
    ] {
        if let Some(bound) = bound {
            let bound = crate::identity::normalized_version(bound)?;
            let ordering = version.cmp(&bound);
            if (lower && (ordering.is_lt() || (!inclusive && ordering.is_eq())))
                || (!lower && (ordering.is_gt() || (!inclusive && ordering.is_eq())))
            {
                return Ok(Some(false));
            }
        }
    }
    Ok(Some(true))
}
fn nvd(instance: &Instance, http: &mut Http<'_>, intelligence: &mut Intelligence) -> Result<()> {
    let product = instance.cpe_product.as_deref().context("no CPE mapping")?;
    let version = instance.resolved_version.as_deref().context("no version")?;
    let mut offset = 0;
    let mut complete = false;
    for _ in 0..10 {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={}&resultsPerPage=2000&startIndex={offset}",
            encode(product)
        );
        let response = http.get(&url)?;
        let page: NvdResponse = response.json()?;
        offset += page.vulnerabilities.len();
        for entry in page.vulnerabilities {
            let cve = entry.cve;
            if cve.status == "Rejected" {
                continue;
            }
            let mut matching = false;
            let mut uncertain = false;
            for configuration in &cve.configurations {
                for node in &configuration.nodes {
                    for candidate in &node.matches {
                        match cpe_applies(candidate, product, version) {
                            Ok(Some(true)) => {
                                matching = true;
                                uncertain |= node.negate
                                    || configuration.negate
                                    || (candidate.criteria.split(':').nth(5) == Some("*")
                                        && candidate.start_including.is_none()
                                        && candidate.start_excluding.is_none()
                                        && candidate.end_including.is_none()
                                        && candidate.end_excluding.is_none())
                                    || candidate
                                        .criteria
                                        .split(':')
                                        .skip(6)
                                        .any(|field| field != "*" && field != "-")
                                    || node.operator == "AND"
                                    || configuration.operator.as_deref() == Some("AND");
                            }
                            Err(_) => {
                                matching = true;
                                uncertain = true;
                            }
                            _ => (),
                        }
                    }
                }
            }
            if !matching {
                continue;
            }
            let evidence = http.store.record_evidence(
                &response.body,
                "nvd",
                Some(url.clone()),
                EvidenceKind::Advisory,
            )?;
            let summary = cve
                .descriptions
                .into_iter()
                .find(|description| description.lang == "en")
                .map(|description| description.value)
                .unwrap_or_else(|| cve.id.clone());
            intelligence.claims.push(Claim {
                id: cve.id,
                source: "nvd".into(),
                aliases: Vec::new(),
                instance_id: instance.id.clone(),
                summary,
                applicability: if uncertain {
                    Applicability::Possible
                } else {
                    Applicability::Affected
                },
                evidence,
                known_exploited: false,
            });
        }
        if offset >= page.total {
            complete = true;
            break;
        }
    }
    intelligence.coverage.push(Coverage::new(
        "nvd",
        &instance.id,
        if complete {
            CoverageState::Checked
        } else {
            CoverageState::Partial
        },
        "validated product CPE; vendor versions and AND/environment conditions remain possible",
    ));
    Ok(())
}
fn enrich(intelligence: &mut Intelligence, instances: &[Instance], http: &mut Http<'_>) {
    let mut cves = HashSet::new();
    for claim in &intelligence.claims {
        for id in std::iter::once(&claim.id).chain(&claim.aliases) {
            if id.starts_with("CVE-") {
                cves.insert(id.clone());
            }
        }
    }
    let kev = http
        .get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        .and_then(|response| {
            let catalog: Kev = response.json()?;
            let evidence = http.store.record_evidence(
                &response.body,
                "cisa_kev",
                Some(response.url),
                EvidenceKind::Context,
            )?;
            Ok((catalog, evidence))
        });
    match kev {
        Ok((kev, evidence)) => {
            let ids: HashSet<String> = kev
                .vulnerabilities
                .into_iter()
                .map(|entry| entry.id)
                .collect();
            for claim in &mut intelligence.claims {
                claim.known_exploited = ids.contains(&claim.id)
                    || claim.aliases.iter().any(|alias| ids.contains(alias));
            }
            let mut prioritized = Vec::new();
            let mut seen = HashSet::new();
            for claim in &intelligence.claims {
                if !claim.known_exploited {
                    continue;
                }
                let cve = std::iter::once(&claim.id)
                    .chain(&claim.aliases)
                    .find(|id| ids.contains(*id))
                    .cloned();
                if let Some(id) = cve
                    && seen.insert((claim.instance_id.clone(), id.clone()))
                {
                    prioritized.push(Claim {id,source:"cisa_kev".into(),aliases:Vec::new(),instance_id:claim.instance_id.clone(),summary:"CISA KEV lists exploitation in the wild; version applicability remains defined by the linked advisory.".into(),applicability:Applicability::Unknown,evidence:evidence.clone(),known_exploited:true});
                }
            }
            intelligence.claims.extend(prioritized);
            intelligence.coverage.push(Coverage::new(
                "cisa_kev",
                "project",
                CoverageState::Checked,
                "prioritization only; KEV does not establish version applicability",
            ));
        }
        Err(error) => intelligence.coverage.push(Coverage::new(
            "cisa_kev",
            "project",
            CoverageState::Partial,
            error.to_string(),
        )),
    }
    for id in cves.iter().take(50) {
        let result = http
            .get(&format!("https://cveawg.mitre.org/api/cve/{id}"))
            .and_then(|response| {
                let record: CveRecord = response.json()?;
                if record.metadata.id != *id {
                    bail!("CVE identity mismatch");
                }
                let evidence = http.store.record_evidence(
                    &response.body,
                    "cve_records",
                    Some(response.url),
                    EvidenceKind::Context,
                )?;
                Ok((record.metadata.state, evidence))
            });
        match result {
            Ok((state, evidence)) => {
                if state == "REJECTED" {
                    let targets: HashSet<String> = intelligence
                        .claims
                        .iter()
                        .filter(|claim| claim.id == *id || claim.aliases.contains(id))
                        .map(|claim| claim.instance_id.clone())
                        .collect();
                    for instance_id in targets {
                        intelligence.claims.push(Claim {id:id.clone(),source:"cve_records".into(),aliases:Vec::new(),instance_id,summary:"The official CVE record is rejected; reassess the related advisory and rejection reason before acting.".into(),applicability:Applicability::Conflict,evidence:evidence.clone(),known_exploited:false});
                    }
                }
                intelligence.coverage.push(Coverage::new(
                    "cve_records",
                    id,
                    if state == "PUBLISHED" {
                        CoverageState::Checked
                    } else {
                        CoverageState::Partial
                    },
                    format!("record state {state}; no PURL equivalence inferred"),
                ));
            }
            Err(error) => intelligence.coverage.push(Coverage::new(
                "cve_records",
                id,
                CoverageState::Partial,
                error.to_string(),
            )),
        }
    }
    if cves.len() > 50 {
        intelligence.coverage.push(Coverage::new(
            "cve_records",
            "project",
            CoverageState::Partial,
            "50-record enrichment budget; advisories still evaluated",
        ));
    }
    let rustsec: Vec<(String, String)> = intelligence
        .claims
        .iter()
        .filter(|claim| claim.id.starts_with("RUSTSEC-"))
        .filter_map(|claim| {
            instances
                .iter()
                .find(|instance| instance.id == claim.instance_id)
                .map(|instance| {
                    (
                        claim.id.clone(),
                        instance.reference.trim_start_matches("pkg:cargo/").into(),
                    )
                })
        })
        .collect();
    for (id, name) in rustsec {
        let result = http
            .get(&format!(
                "https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/{}/{id}.md",
                encode(&name)
            ))
            .and_then(|response| {
                let text = std::str::from_utf8(&response.body)?;
                let block = text
                    .strip_prefix("```toml\n")
                    .context("RustSec TOML frontmatter missing")?
                    .split("\n```")
                    .next()
                    .context("RustSec frontmatter incomplete")?;
                let _: toml::Value = toml::from_str(block)?;
                http.store.record_evidence(
                    &response.body,
                    "rustsec_native",
                    Some(response.url),
                    EvidenceKind::Context,
                )?;
                Ok(())
            });
        intelligence.coverage.push(Coverage::new(
            "rustsec_native",
            &id,
            if result.is_ok() {
                CoverageState::Checked
            } else {
                CoverageState::Partial
            },
            match result {
                Ok(()) => {
                    "native RustSec record retrieved; applicability from exact OSV RustSec query"
                        .into()
                }
                Err(error) => error.to_string(),
            },
        ));
    }
}

#[cfg(test)]
mod tests;
