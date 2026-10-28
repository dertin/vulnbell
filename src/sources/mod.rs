use crate::{
    model::{
        Applicability, Case, Claim, Coverage, CoverageState, Evidence, EvidenceKind, Instance,
    },
    network::Http,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

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
                            let excluded = match (&instance.purl, &instance.resolved_version) {
                                (Some(purl), Some(version)) => {
                                    osv_ranges_exclude(&document, purl, version)
                                }
                                _ => false,
                            };
                            let mut evidence = evidence.clone();
                            if excluded {
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
                                applicability: if excluded {
                                    Applicability::NotAffected
                                } else {
                                    Applicability::Affected
                                },
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
                intelligence.coverage.push(Coverage::new("osv", &instance.id, if complete { CoverageState::Checked } else { CoverageState::Partial }, "exact-version batch query; withdrawn records excluded; detail/pagination failures reduce coverage"));
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

#[derive(Deserialize)]
struct RepositoryAdvisory {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    withdrawn_at: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<RepositoryVulnerability>,
}
#[derive(Deserialize)]
struct RepositoryVulnerability {
    package: Option<RepositoryPackage>,
    vulnerable_version_range: Option<String>,
    patched_versions: Option<String>,
}
#[derive(Deserialize)]
struct RepositoryPackage {
    ecosystem: String,
    name: Option<String>,
}

/// Match an official published GitHub repository advisory to an existing case's exact instances.
/// Arbitrary web documents and advisory links to other repositories remain context only.
pub fn case_repository_advisory(
    case: &Case,
    url: &str,
    bytes: &[u8],
    evidence: &Evidence,
) -> Option<(String, Vec<Claim>)> {
    let Ok(url) = url::Url::parse(url) else {
        return None;
    };
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let segments: Vec<&str> = url.path_segments().into_iter().flatten().collect();
    let ["repos", owner, repository, "security-advisories", id] = segments.as_slice() else {
        return None;
    };
    let expected = format!("https://github.com/{owner}/{repository}/security/advisories/{id}");
    if !case
        .upstream_events
        .iter()
        .any(|event| event.url == expected)
    {
        return None;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return None;
    };
    let state = value.get("state").and_then(serde_json::Value::as_str)?;
    if state != "published" && state != "withdrawn" {
        return None;
    }
    let withdrawn = state == "withdrawn";
    let Ok(advisory) = serde_json::from_value::<RepositoryAdvisory>(value) else {
        return None;
    };
    if advisory.ghsa_id != *id {
        return None;
    }
    if withdrawn || advisory.withdrawn_at.is_some() {
        return Some((id.to_string(), Vec::new()));
    }
    let expected_repository = format!("{owner}/{repository}");
    let mut claims = Vec::new();
    for instance in &case.instances {
        if instance
            .upstream
            .as_deref()
            .and_then(github_repository)
            .as_deref()
            != Some(expected_repository.as_str())
        {
            continue;
        }
        let Some(version) = instance
            .resolved_version
            .as_deref()
            .and_then(|value| crate::identity::normalized_version(value).ok())
        else {
            continue;
        };
        let affected = advisory.vulnerabilities.iter().any(|vulnerability| {
            let Some(package) = &vulnerability.package else {
                return false;
            };
            package
                .name
                .as_deref()
                .is_some_and(|name| repository_package_is(instance, &package.ecosystem, name))
                && vulnerability
                    .vulnerable_version_range
                    .as_deref()
                    .and_then(|range| {
                        github_range_match(
                            range,
                            vulnerability.patched_versions.as_deref(),
                            &version,
                        )
                    })
                    == Some(RangeMatch::Affected)
        });
        if affected {
            let mut evidence = evidence.clone();
            evidence.kind = EvidenceKind::Advisory;
            claims.push(Claim {
                id: advisory.ghsa_id.clone(),
                source: "github_repository".into(),
                aliases: advisory.cve_id.iter().cloned().collect(),
                instance_id: instance.id.clone(),
                summary: advisory.summary.clone(),
                applicability: Applicability::Affected,
                evidence,
                known_exploited: false,
            });
        }
    }
    Some((id.to_string(), claims))
}

/// Advisories that maintainers publish in their repository reach the global GitHub database
/// and OSV only after GitHub reviews them; until then the repository is the vendor's statement.
fn repository_advisories(
    instances: &[Instance],
    http: &mut Http<'_>,
    intelligence: &mut Intelligence,
    research: &crate::profile::Research,
    previous_cases: &[Case],
) {
    // A previously observed repository advisory is a concrete reason to refresh that source
    // even for a deferred dependency; this does not expand its issues/PR tracker scope.
    let previously_claimed: std::collections::HashSet<&str> = previous_cases
        .iter()
        .flat_map(|case| &case.claims)
        .filter(|claim| claim.source == "github_repository")
        .map(|claim| claim.instance_id.as_str())
        .collect();
    let mut by_repository: BTreeMap<String, Vec<(&Instance, &'static str, String)>> =
        BTreeMap::new();
    for instance in instances.iter().filter(|instance| {
        research.tracks(instance) || previously_claimed.contains(instance.id.as_str())
    }) {
        if instance.resolved_version.is_none() {
            continue;
        }
        let Some(repository) = instance.upstream.as_deref().and_then(github_repository) else {
            continue;
        };
        let Ok(Some((ecosystem, name))) = github_package(instance) else {
            continue;
        };
        by_repository
            .entry(repository)
            .or_default()
            .push((instance, ecosystem, name));
    }
    for (repository, members) in by_repository {
        let (state, detail) = match repository_claims(
            &repository,
            &members,
            http,
            &mut intelligence.claims,
        ) {
            Ok(unevaluable) if unevaluable.is_empty() => (
                CoverageState::Checked,
                format!("published security advisories of {repository}"),
            ),
            Ok(unevaluable) => (
                CoverageState::Partial,
                format!(
                    "published security advisories of {repository}; ranges not evaluable without guessing: {}",
                    unevaluable.join(", ")
                ),
            ),
            Err(error) => (CoverageState::Partial, error.to_string()),
        };
        for (instance, _, _) in members {
            intelligence.coverage.push(Coverage::new(
                "repository_advisories",
                &instance.id,
                state,
                &detail,
            ));
        }
    }
}

/// Pushes affected claims and returns the advisory IDs whose range could not be evaluated.
fn repository_claims(
    repository: &str,
    members: &[(&Instance, &'static str, String)],
    http: &mut Http<'_>,
    claims: &mut Vec<Claim>,
) -> Result<Vec<String>> {
    let mut unevaluable = Vec::new();
    for page in 1..=10 {
        let url = format!(
            "https://api.github.com/repos/{repository}/security-advisories?state=published&per_page=100&page={page}"
        );
        let response = http.get(&url)?;
        let advisories: Vec<RepositoryAdvisory> = response.json()?;
        let length = advisories.len();
        let evidence = http.store.record_evidence(
            &response.body,
            "github_repository_advisories",
            Some(url),
            EvidenceKind::Advisory,
        )?;
        for advisory in advisories {
            if advisory.withdrawn_at.is_some() {
                continue;
            }
            for (instance, ecosystem, name) in members {
                let Some(Ok(version)) = instance
                    .resolved_version
                    .as_deref()
                    .map(crate::identity::normalized_version)
                else {
                    continue;
                };
                let mut strongest = RangeMatch::Outside;
                for vulnerability in &advisory.vulnerabilities {
                    let Some(package) = &vulnerability.package else {
                        continue;
                    };
                    if package.ecosystem != *ecosystem
                        || !package.name.as_deref().is_some_and(|advisory_name| {
                            same_package(ecosystem, advisory_name, name)
                        })
                    {
                        continue;
                    }
                    match vulnerability
                        .vulnerable_version_range
                        .as_deref()
                        .and_then(|range| {
                            github_range_match(
                                range,
                                vulnerability.patched_versions.as_deref(),
                                &version,
                            )
                        }) {
                        Some(found) => strongest = strongest.max(found),
                        None => unevaluable.push(advisory.ghsa_id.clone()),
                    }
                }
                let (applicability, kind) = match strongest {
                    RangeMatch::Outside => continue,
                    RangeMatch::FixedOnLine => {
                        (Applicability::NotAffected, EvidenceKind::NonApplicability)
                    }
                    RangeMatch::Affected => (Applicability::Affected, EvidenceKind::Advisory),
                };
                let mut evidence = evidence.clone();
                evidence.kind = kind;
                claims.push(Claim {
                    id: advisory.ghsa_id.clone(),
                    source: "github_repository".into(),
                    aliases: advisory.cve_id.iter().cloned().collect(),
                    instance_id: instance.id.clone(),
                    summary: advisory.summary.clone(),
                    applicability,
                    evidence,
                    known_exploited: false,
                });
            }
        }
        if length < 100 && !response.truncated {
            unevaluable.sort_unstable();
            unevaluable.dedup();
            return Ok(unevaluable);
        }
    }
    bail!("more than 10 pages of repository advisories")
}

/// `owner/repo` of a GitHub repository URL.
fn github_repository(upstream: &str) -> Option<String> {
    let path = upstream.strip_prefix("https://github.com/")?;
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    let owner = segments.next()?;
    let repository = segments.next()?.trim_end_matches(".git");
    if repository.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repository}"))
}

/// Whether a package named by a repository advisory is this instance.
pub(crate) fn repository_package_is(
    instance: &Instance,
    advisory_ecosystem: &str,
    advisory_name: &str,
) -> bool {
    matches!(
        github_package(instance),
        Ok(Some((ecosystem, name)))
            if ecosystem == advisory_ecosystem && same_package(ecosystem, advisory_name, &name)
    )
}

pub(crate) fn same_package(ecosystem: &str, advisory_name: &str, name: &str) -> bool {
    match ecosystem {
        "maven" => advisory_name.replace(':', "/") == name,
        "pip" => {
            let normalize = |value: &str| value.to_ascii_lowercase().replace(['_', '.'], "-");
            normalize(advisory_name) == normalize(name)
        }
        _ => advisory_name == name,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RangeMatch {
    Outside,
    /// The range alone contains the version, but `patched_versions` closes it before.
    FixedOnLine,
    Affected,
}

/// GitHub ranges are comma-separated comparators (`>= 3.0.0, < 3.6.0`) or a list of exact
/// versions (`0.23.44,0.23.45`). Maintainers often state only a lower bound and leave the end
/// to `patched_versions`. `None` when any term needs guessing or the bounds contradict.
pub(crate) fn github_range_match(
    range: &str,
    patched: Option<&str>,
    version: &semver::Version,
) -> Option<RangeMatch> {
    let terms: Vec<&str> = range
        .split(',')
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .collect();
    if terms.is_empty() {
        return None;
    }
    if terms
        .iter()
        .all(|term| term.starts_with(|first: char| first.is_ascii_digit()))
    {
        let mut listed = RangeMatch::Outside;
        for term in terms {
            if &crate::identity::normalized_version(term).ok()? == version {
                listed = RangeMatch::Affected;
            }
        }
        return Some(listed);
    }
    let mut contains = true;
    let mut lower: Option<semver::Version> = None;
    let mut upper: Option<semver::Version> = None;
    for term in terms {
        let (operator, value) = ["<=", ">=", "<", ">", "="]
            .into_iter()
            .find_map(|operator| Some((operator, term.strip_prefix(operator)?.trim())))?;
        if value.contains(char::is_whitespace) {
            return None;
        }
        let bound = crate::identity::normalized_version(value).ok()?;
        contains &= match operator {
            "<=" => version <= &bound,
            ">=" => version >= &bound,
            "<" => version < &bound,
            ">" => version > &bound,
            _ => version == &bound,
        };
        if operator != "<" && operator != "<=" && lower.as_ref().is_none_or(|kept| &bound > kept) {
            lower = Some(bound.clone());
        }
        if operator != ">" && operator != ">=" && upper.as_ref().is_none_or(|kept| &bound < kept) {
            upper = Some(bound);
        }
    }
    if let (Some(lower), Some(upper)) = (&lower, &upper)
        && lower > upper
    {
        return None;
    }
    if !contains {
        return Some(RangeMatch::Outside);
    }
    match patched.map(str::trim).filter(|patched| !patched.is_empty()) {
        Some(patched) if upper.is_none() => {
            patched_line_excludes(patched, version).map(|excluded| {
                if excluded {
                    RangeMatch::FixedOnLine
                } else {
                    RangeMatch::Affected
                }
            })
        }
        // A sole fix inside the range at or below the version contradicts the range
        // (`>= 2.21.0, <= 2.22.0` patched in `2.21.5`, or a typo such as `< 26.37.1` patched in
        // `26.7.1`); which side the maintainer meant cannot be told.
        Some(patched)
            if sole_fix(patched).is_some_and(|fix| {
                &fix <= version && lower.as_ref().is_none_or(|lower| &fix >= lower)
            }) =>
        {
            None
        }
        _ => Some(RangeMatch::Affected),
    }
}

fn sole_fix(patched: &str) -> Option<semver::Version> {
    let mut items = patched
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty());
    let item = items.next()?;
    if items.next().is_some() {
        return None;
    }
    crate::identity::normalized_version(item.trim_start_matches(['>', '=', '~', '^']).trim()).ok()
}

/// Whether the version is at or past the fix of its release line; a fix per line is common
/// (`0.104.0-alpha.5, 0.103.10`). `None` when the line cannot be told.
fn patched_line_excludes(patched: &str, version: &semver::Version) -> Option<bool> {
    let mut fixes = Vec::new();
    for item in patched
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let value = item.trim_start_matches(['>', '=', '~', '^']).trim();
        fixes.push(crate::identity::normalized_version(value).ok()?);
    }
    if let [fix] = fixes.as_slice() {
        return Some(version >= fix);
    }
    let line = |value: &semver::Version| {
        if value.major == 0 {
            (0, value.minor)
        } else {
            (value.major, 0)
        }
    };
    if let Some(fix) = fixes.iter().find(|fix| line(fix) == line(version)) {
        return Some(version >= fix);
    }
    if !fixes.is_empty() && fixes.iter().all(|fix| version > fix) {
        return Some(true);
    }
    None
}
pub fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
/// GHSA ranges without a patched version reach OSV as an open `introduced: "0"` range; the real
/// bound survives only in `database_specific.last_known_affected_version_range`, so OSV matches
/// every later version. True only when every entry for this package can be evaluated and none
/// contains the version; any doubt keeps the match.
fn osv_ranges_exclude(advisory: &serde_json::Value, purl: &str, version: &str) -> bool {
    let Ok(version) = crate::identity::normalized_version(version) else {
        return false;
    };
    let base = purl.split(['@', '?', '#']).next().unwrap_or(purl);
    let Some(entries) = advisory
        .get("affected")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let mut matched = false;
    for entry in entries {
        match entry
            .pointer("/package/purl")
            .and_then(serde_json::Value::as_str)
        {
            Some(entry_purl) if entry_purl.split(['@', '?', '#']).next() == Some(base) => {}
            Some(_) => continue,
            None => return false,
        }
        matched = true;
        if osv_entry_contains(entry, &version) != Some(false) {
            return false;
        }
    }
    matched
}

/// `None` when the entry cannot be evaluated without guessing (Git ranges, unparsable versions,
/// compound GHSA bounds).
pub(crate) fn osv_entry_contains(
    entry: &serde_json::Value,
    version: &semver::Version,
) -> Option<bool> {
    let parse = |value: &str| {
        if value == "0" {
            Some(semver::Version::new(0, 0, 0))
        } else {
            crate::identity::normalized_version(value).ok()
        }
    };
    let ranges = entry.get("ranges")?.as_array()?;
    let ghsa_bound = entry
        .pointer("/database_specific/last_known_affected_version_range")
        .and_then(serde_json::Value::as_str);
    let open_only = ranges.iter().all(|range| {
        range
            .get("events")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|events| {
                events.len() == 1
                    && events[0]
                        .get("introduced")
                        .and_then(serde_json::Value::as_str)
                        == Some("0")
            })
    });
    // The enumerated versions of an open GHSA range repeat the conversion error.
    if !(open_only && ghsa_bound.is_some())
        && entry
            .get("versions")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|listed| {
                listed
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(parse)
                    .any(|listed| &listed == version)
            })
    {
        return Some(true);
    }
    for range in ranges {
        if range.get("type")?.as_str()? == "GIT" {
            return None;
        }
        let mut start: Option<semver::Version> = None;
        for event in range.get("events")?.as_array()? {
            let (kind, value) = event.as_object()?.iter().next()?;
            let bound = parse(value.as_str()?)?;
            match kind.as_str() {
                "introduced" => start = Some(bound),
                "fixed" | "limit" => {
                    if start
                        .take()
                        .is_some_and(|start| &start <= version && version < &bound)
                    {
                        return Some(true);
                    }
                }
                "last_affected" => {
                    if start
                        .take()
                        .is_some_and(|start| &start <= version && version <= &bound)
                    {
                        return Some(true);
                    }
                }
                _ => return None,
            }
        }
        if start.is_some_and(|start| &start <= version) {
            let bound = ghsa_bound?.trim();
            if bound.contains(',') {
                return None;
            }
            let (inclusive, value) = match bound.strip_prefix("<=") {
                Some(value) => (true, value),
                None => (false, bound.strip_prefix('<')?),
            };
            let upper = parse(value.trim())?;
            if version < &upper || inclusive && version == &upper {
                return Some(true);
            }
        }
    }
    Some(false)
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
