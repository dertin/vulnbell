//! Resolution of advisory IDs cited by upstream items: the GitHub Advisory Database, then OSV,
//! then the CVE record's CNA title. Each affected package is matched to the monitored inventory
//! with the same range evaluation the scan uses.
use crate::{
    model::Instance,
    network::Http,
    sources::{
        RangeMatch, github_range_match, osv_package_identity, osv_ranges_match,
        repository_package_match,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const TITLE_LIMIT: usize = 300;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BuildStatus {
    Outside,
    /// The range contains the version, but the advisory's fix for that release line is older.
    FixedOnLine,
    /// The range cannot be evaluated without guessing.
    Unknown,
    Affected,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildMatch {
    pub instance_id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub version: String,
    pub status: BuildStatus,
    pub range: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Resolution {
    pub id: String,
    pub title: String,
    /// A public advisory database lists affected packages for this ID.
    pub published: bool,
    /// `ecosystem:name` of every affected package.
    pub packages: Vec<String>,
    /// Monitored instances that are one of the affected packages, with the strongest match each.
    pub in_build: Vec<BuildMatch>,
    pub sources: Vec<String>,
    pub errors: Vec<String>,
}

impl Resolution {
    /// Whether a monitored instance is, or may be, inside an affected range.
    pub fn may_affect_build(&self) -> bool {
        !self.errors.is_empty()
            || self
                .in_build
                .iter()
                .any(|found| matches!(found.status, BuildStatus::Affected | BuildStatus::Unknown))
    }
}

pub fn resolve(
    ids: &BTreeSet<String>,
    instances: &[Instance],
    http: &mut Http<'_>,
) -> BTreeMap<String, Resolution> {
    let mut resolved = BTreeMap::new();
    for id in ids {
        let mut resolution = Resolution {
            id: id.clone(),
            ..Resolution::default()
        };
        if id.starts_with("GHSA-") || id.starts_with("CVE-") {
            github(id, instances, http, &mut resolution);
        }
        if resolution.packages.is_empty() {
            osv(id, instances, http, &mut resolution);
        }
        if resolution.title.is_empty() && id.starts_with("CVE-") {
            cve_record(id, http, &mut resolution);
        }
        resolution.packages.sort_unstable();
        resolution.packages.dedup();
        resolution.published = !resolution.packages.is_empty();
        resolved.insert(id.clone(), resolution);
    }
    resolved
}

/// `Ok(None)` for a 404, which means the database has no record for the ID.
fn fetch(http: &mut Http<'_>, url: &str) -> Result<Option<Value>, String> {
    match http.get(url).and_then(|response| response.json::<Value>()) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.to_string().contains("HTTP 404") => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn record_match(
    resolution: &mut Resolution,
    instance: &Instance,
    status: BuildStatus,
    range: &str,
) {
    let version = instance.resolved_version.clone().unwrap_or_default();
    match resolution
        .in_build
        .iter_mut()
        .find(|found| found.instance_id == instance.id)
    {
        Some(found) if found.status < status => {
            found.status = status;
            found.range = range.to_owned();
        }
        Some(_) => {}
        None => resolution.in_build.push(BuildMatch {
            instance_id: instance.id.clone(),
            reference: instance.reference.clone(),
            version,
            status,
            range: range.to_owned(),
        }),
    }
}

#[derive(Deserialize)]
struct GlobalPackage {
    ecosystem: String,
    name: Option<String>,
}
#[derive(Deserialize)]
struct GlobalVulnerability {
    package: Option<GlobalPackage>,
    vulnerable_version_range: Option<String>,
    first_patched_version: Option<Value>,
}
#[derive(Deserialize)]
struct GlobalAdvisory {
    summary: String,
    withdrawn_at: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<GlobalVulnerability>,
}

fn github(id: &str, instances: &[Instance], http: &mut Http<'_>, resolution: &mut Resolution) {
    let url = if id.starts_with("GHSA-") {
        format!("https://api.github.com/advisories/{id}")
    } else {
        format!(
            "https://api.github.com/advisories?cve_id={}",
            crate::sources::encode(id)
        )
    };
    let value = match fetch(http, &url) {
        Ok(Some(value)) => value,
        Ok(None) => return,
        Err(error) => {
            resolution.errors.push(format!("github: {error}"));
            return;
        }
    };
    let records = match value {
        Value::Array(records) => records,
        record => vec![record],
    };
    for record in records {
        let Ok(advisory) = serde_json::from_value::<GlobalAdvisory>(record) else {
            resolution
                .errors
                .push("github: unexpected advisory shape".into());
            continue;
        };
        if advisory.withdrawn_at.is_some() {
            continue;
        }
        resolution.sources.push("github".into());
        if resolution.title.is_empty() {
            resolution.title = super::truncate_chars(&advisory.summary, TITLE_LIMIT);
        }
        for vulnerability in advisory.vulnerabilities {
            let Some(GlobalPackage {
                ecosystem,
                name: Some(name),
            }) = vulnerability.package
            else {
                for instance in instances {
                    record_match(
                        resolution,
                        instance,
                        BuildStatus::Unknown,
                        "package identity unavailable",
                    );
                }
                continue;
            };
            resolution.packages.push(format!("{ecosystem}:{name}"));
            let range = vulnerability.vulnerable_version_range.unwrap_or_default();
            let patched = vulnerability
                .first_patched_version
                .as_ref()
                .and_then(|value| {
                    value
                        .as_str()
                        .or_else(|| value.get("identifier").and_then(Value::as_str))
                        .map(str::to_owned)
                });
            for instance in instances {
                match repository_package_match(instance, &ecosystem, &name) {
                    Some(true) => {}
                    Some(false) => continue,
                    None => {
                        record_match(
                            resolution,
                            instance,
                            BuildStatus::Unknown,
                            "package identity unavailable",
                        );
                        continue;
                    }
                }
                let status = instance
                    .resolved_version
                    .as_deref()
                    .and_then(|version| {
                        github_range_match(&range, patched.as_deref(), version, &ecosystem)
                    })
                    .map(|found| match found {
                        RangeMatch::Outside => BuildStatus::Outside,
                        RangeMatch::FixedOnLine => BuildStatus::FixedOnLine,
                        RangeMatch::Affected => BuildStatus::Affected,
                    })
                    .unwrap_or(BuildStatus::Unknown);
                record_match(resolution, instance, status, &range);
            }
        }
    }
}

fn osv(id: &str, instances: &[Instance], http: &mut Http<'_>, resolution: &mut Resolution) {
    let url = format!(
        "https://api.osv.dev/v1/vulns/{}",
        crate::sources::encode(id)
    );
    let record = match fetch(http, &url) {
        Ok(Some(record)) => record,
        Ok(None) => return,
        Err(error) => {
            resolution.errors.push(format!("osv: {error}"));
            return;
        }
    };
    if record
        .get("withdrawn")
        .is_some_and(|value| !value.is_null())
    {
        return;
    }
    resolution.sources.push("osv".into());
    if resolution.title.is_empty() {
        let title = record
            .get("summary")
            .or_else(|| record.get("details"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        resolution.title = super::truncate_chars(title, TITLE_LIMIT);
    }
    osv_record(&record, instances, resolution);
}

pub(super) fn osv_record(record: &Value, instances: &[Instance], resolution: &mut Resolution) {
    let entries = record
        .get("affected")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in &entries {
        let ecosystem = entry
            .pointer("/package/ecosystem")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = entry
            .pointer("/package/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !name.is_empty() {
            resolution.packages.push(format!("{ecosystem}:{name}"));
        } else if let Some(purl) = entry.pointer("/package/purl").and_then(Value::as_str) {
            resolution.packages.push(purl.to_owned());
        }
    }
    for instance in instances {
        let version = instance.resolved_version.as_deref();
        let purl = instance.purl.as_deref();
        if entries
            .iter()
            .all(|entry| osv_package_identity(&entry["package"], purl, version) == Some(false))
        {
            continue;
        }
        let status = purl
            .zip(version)
            .and_then(|(purl, version)| osv_ranges_match(record, purl, version))
            .map(|contains| {
                if contains {
                    BuildStatus::Affected
                } else {
                    BuildStatus::Outside
                }
            })
            .unwrap_or(BuildStatus::Unknown);
        record_match(resolution, instance, status, "OSV ranges");
    }
}

fn cve_record(id: &str, http: &mut Http<'_>, resolution: &mut Resolution) {
    let url = format!("https://cveawg.mitre.org/api/cve/{id}");
    let record = match fetch(http, &url) {
        Ok(Some(record)) => record,
        Ok(None) => return,
        Err(error) => {
            resolution.errors.push(format!("cve.org: {error}"));
            return;
        }
    };
    let title = record
        .pointer("/containers/cna/title")
        .or_else(|| record.pointer("/containers/cna/descriptions/0/value"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !title.is_empty() {
        resolution.sources.push("cve.org".into());
        resolution.title = super::truncate_chars(title, TITLE_LIMIT);
    }
}

#[cfg(test)]
mod tests;
