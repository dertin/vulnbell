use super::{Intelligence, github_package};
use crate::{
    model::{
        Applicability, Case, Claim, Coverage, CoverageState, Evidence, EvidenceKind, Instance,
    },
    network::Http,
};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
pub(super) struct RepositoryAdvisory {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    withdrawn_at: Option<String>,
    #[serde(default)]
    pub(super) vulnerabilities: Vec<RepositoryVulnerability>,
}
#[derive(Deserialize)]
pub(super) struct RepositoryVulnerability {
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
        let same_upstream = instance
            .upstream
            .as_deref()
            .and_then(github_repository)
            .as_deref()
            == Some(expected_repository.as_str());
        let prior_claim = case.claims.iter().any(|claim| {
            claim.source == "github_repository"
                && claim.id == *id
                && claim.instance_id == instance.id
        });
        if !same_upstream && !prior_claim {
            continue;
        }
        let applicability = if same_upstream {
            repository_assessment(&advisory, instance).0
        } else {
            Some(Applicability::Unknown)
        };
        if let Some(applicability) = applicability {
            let mut evidence = evidence.clone();
            evidence.kind = if applicability == Applicability::NotAffected {
                EvidenceKind::NonApplicability
            } else {
                EvidenceKind::Advisory
            };
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
    Some((id.to_string(), claims))
}

/// Advisories that maintainers publish in their repository reach the global GitHub database
/// and OSV only after GitHub reviews them; until then the repository is the vendor's statement.
pub(super) fn repository_advisories(
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
                    "published security advisories of {repository}; package identity or version range not evaluable: {}",
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

/// Pushes matching claims and returns advisory IDs whose range could not be evaluated.
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
            for (instance, _, _) in members {
                let (applicability, unresolved) = repository_assessment(&advisory, instance);
                if unresolved {
                    unevaluable.push(advisory.ghsa_id.clone());
                }
                let Some(applicability) = applicability else {
                    continue;
                };
                let kind = if applicability == Applicability::NotAffected {
                    EvidenceKind::NonApplicability
                } else {
                    EvidenceKind::Advisory
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

fn repository_assessment(
    advisory: &RepositoryAdvisory,
    instance: &Instance,
) -> (Option<Applicability>, bool) {
    let mut strongest = RangeMatch::Outside;
    let mut unresolved = advisory.vulnerabilities.is_empty();
    for vulnerability in &advisory.vulnerabilities {
        let Some(package) = &vulnerability.package else {
            unresolved = true;
            continue;
        };
        let Some(name) = package.name.as_deref().filter(|name| !name.is_empty()) else {
            unresolved = true;
            continue;
        };
        match repository_package_match(instance, &package.ecosystem, name) {
            Some(true) => {}
            Some(false) => continue,
            None => {
                unresolved = true;
                continue;
            }
        }
        let matched = instance.resolved_version.as_deref().and_then(|version| {
            vulnerability
                .vulnerable_version_range
                .as_deref()
                .and_then(|range| {
                    github_range_match(
                        range,
                        vulnerability.patched_versions.as_deref(),
                        version,
                        &package.ecosystem,
                    )
                })
        });
        match matched {
            Some(found) => strongest = strongest.max(found),
            None => unresolved = true,
        }
    }
    let applicability = match strongest {
        RangeMatch::Affected => Some(Applicability::Affected),
        _ if unresolved => Some(Applicability::Unknown),
        RangeMatch::Outside => None,
        RangeMatch::FixedOnLine => Some(Applicability::NotAffected),
    };
    (applicability, unresolved)
}

/// `owner/repo` of a GitHub repository URL.
pub(super) fn github_repository(upstream: &str) -> Option<String> {
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
    repository_package_match(instance, advisory_ecosystem, advisory_name) == Some(true)
}

pub(crate) fn repository_package_match(
    instance: &Instance,
    advisory_ecosystem: &str,
    advisory_name: &str,
) -> Option<bool> {
    if advisory_ecosystem.is_empty() || advisory_name.is_empty() {
        return None;
    }
    let (ecosystem, name) = github_package(instance).ok()??;
    if ecosystem != advisory_ecosystem {
        return Some(false);
    }
    if same_package(ecosystem, advisory_name, &name) {
        return Some(true);
    }
    let advisory_name = if ecosystem == "maven" {
        advisory_name.replace(':', "/")
    } else {
        advisory_name.to_owned()
    };
    if advisory_name.eq_ignore_ascii_case(&name) {
        None
    } else {
        Some(false)
    }
}

pub(crate) fn same_package(ecosystem: &str, advisory_name: &str, name: &str) -> bool {
    match ecosystem {
        "maven" => advisory_name.replace(':', "/") == name,
        "pip" => super::normalize_pypi(advisory_name) == super::normalize_pypi(name),
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
fn github_version_orderable(ecosystem: &str, value: &str) -> bool {
    super::ecosystem_version_orderable(ecosystem, value)
        && (!matches!(ecosystem, "npm" | "rust" | "cargo" | "crates.io")
            || semver::Version::parse(value).is_ok_and(|version| version.pre.is_empty()))
}

pub(crate) fn github_range_match(
    range: &str,
    patched: Option<&str>,
    raw_version: &str,
    ecosystem: &str,
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
        if terms.contains(&raw_version) {
            return Some(RangeMatch::Affected);
        }
        if !super::ecosystem_version_orderable(ecosystem, raw_version)
            || terms
                .iter()
                .any(|term| !super::ecosystem_version_orderable(ecosystem, term))
        {
            return None;
        }
        let version = crate::identity::normalized_version(raw_version).ok()?;
        return Some(
            if terms.iter().any(|term| {
                crate::identity::normalized_version(term).ok().as_ref() == Some(&version)
            }) {
                RangeMatch::Affected
            } else {
                RangeMatch::Outside
            },
        );
    }
    if terms.len() == 1
        && patched.is_none()
        && terms[0]
            .strip_prefix('=')
            .is_some_and(|value| value.trim() == raw_version)
    {
        return Some(RangeMatch::Affected);
    }
    if !github_version_orderable(ecosystem, raw_version) {
        return None;
    }
    for term in &terms {
        let value = ["<=", ">=", "<", ">", "="]
            .into_iter()
            .find_map(|operator| term.strip_prefix(operator))?
            .trim();
        if !github_version_orderable(ecosystem, value) {
            return None;
        }
    }
    if let Some(patched) = patched {
        for item in patched
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let value = item.trim_start_matches(['>', '=', '~', '^']).trim();
            if !github_version_orderable(ecosystem, value)
                || (item.starts_with(['~', '^'])
                    && !matches!(ecosystem, "npm" | "rust" | "cargo" | "crates.io"))
            {
                return None;
            }
        }
    }
    let version = super::precedence_version(raw_version)?;
    let version = &version;
    let mut contains = true;
    let mut lower: Option<(semver::Version, bool)> = None;
    let mut upper: Option<(semver::Version, bool)> = None;
    for term in terms {
        let (operator, value) = ["<=", ">=", "<", ">", "="]
            .into_iter()
            .find_map(|operator| Some((operator, term.strip_prefix(operator)?.trim())))?;
        if value.contains(char::is_whitespace) {
            return None;
        }
        let bound = super::precedence_version(value)?;
        contains &= match operator {
            "<=" => version <= &bound,
            ">=" => version >= &bound,
            "<" => version < &bound,
            ">" => version > &bound,
            _ => version == &bound,
        };
        let inclusive = matches!(operator, "<=" | ">=" | "=");
        if operator != "<"
            && operator != "<="
            && lower.as_ref().is_none_or(|(kept, kept_inclusive)| {
                &bound > kept || (&bound == kept && !inclusive && *kept_inclusive)
            })
        {
            lower = Some((bound.clone(), inclusive));
        }
        if operator != ">"
            && operator != ">="
            && upper.as_ref().is_none_or(|(kept, kept_inclusive)| {
                &bound < kept || (&bound == kept && !inclusive && *kept_inclusive)
            })
        {
            upper = Some((bound, inclusive));
        }
    }
    if let (Some((lower, lower_inclusive)), Some((upper, upper_inclusive))) = (&lower, &upper)
        && (lower > upper || (lower == upper && (!lower_inclusive || !upper_inclusive)))
    {
        return None;
    }
    if !contains {
        return Some(RangeMatch::Outside);
    }
    let patched = patched.map(str::trim).filter(|patched| !patched.is_empty());
    if let Some(patched) = patched {
        for item in patched.split(',').map(str::trim) {
            PatchedVersion::parse(item)?;
        }
    }
    match patched {
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
                fix.matches(version)
                    && lower
                        .as_ref()
                        .is_none_or(|(lower, _)| &fix.version >= lower)
            }) =>
        {
            None
        }
        _ => Some(RangeMatch::Affected),
    }
}

fn sole_fix(patched: &str) -> Option<PatchedVersion> {
    let mut items = patched
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty());
    let item = items.next()?;
    if items.next().is_some() {
        return None;
    }
    PatchedVersion::parse(item)
}

enum PatchedOperator {
    Version,
    Greater,
    GreaterEqual,
    Equal,
    Requirement(semver::VersionReq),
}

struct PatchedVersion {
    version: semver::Version,
    operator: PatchedOperator,
}

impl PatchedVersion {
    fn parse(item: &str) -> Option<Self> {
        let (operator, value) = if let Some(value) = item.strip_prefix(">=") {
            (">=", value)
        } else if let Some(value) = item.strip_prefix('>') {
            (">", value)
        } else if let Some(value) = item.strip_prefix('=') {
            ("=", value)
        } else if let Some(value) = item.strip_prefix('~') {
            ("~", value)
        } else if let Some(value) = item.strip_prefix('^') {
            ("^", value)
        } else {
            ("", item)
        };
        let version = super::precedence_version(value.trim())?;
        let operator = match operator {
            ">=" => PatchedOperator::GreaterEqual,
            ">" => PatchedOperator::Greater,
            "=" => PatchedOperator::Equal,
            "~" | "^" => PatchedOperator::Requirement(
                semver::VersionReq::parse(&format!("{operator}{version}")).ok()?,
            ),
            _ => PatchedOperator::Version,
        };
        Some(Self { version, operator })
    }

    fn matches(&self, version: &semver::Version) -> bool {
        match &self.operator {
            PatchedOperator::Version | PatchedOperator::GreaterEqual => version >= &self.version,
            PatchedOperator::Greater => version > &self.version,
            PatchedOperator::Equal => version == &self.version,
            PatchedOperator::Requirement(requirement) => requirement.matches(version),
        }
    }
}

/// Whether an explicit patched range or a fix on the same release line covers the version.
fn patched_line_excludes(patched: &str, version: &semver::Version) -> Option<bool> {
    let mut result = None;
    for item in patched
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let fix = PatchedVersion::parse(item)?;
        let same_line = fix.version.major == version.major && fix.version.minor == version.minor;
        let fixed = match &fix.operator {
            PatchedOperator::Version if same_line => Some(fix.matches(version)),
            PatchedOperator::Greater | PatchedOperator::GreaterEqual
                if fix.matches(version) || same_line =>
            {
                Some(fix.matches(version))
            }
            PatchedOperator::Equal | PatchedOperator::Requirement(_) if fix.matches(version) => {
                Some(true)
            }
            _ => None,
        };
        if let Some(fixed) = fixed {
            if result.is_some_and(|prior| prior != fixed) {
                return None;
            }
            result = Some(fixed);
        }
    }
    result
}
