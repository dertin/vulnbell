use crate::{model::Instance, store::Store};
use anyhow::Result;
use serde::Deserialize;

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct AdvisoryDetail {
    pub source: String,
    pub advisory_id: String,
    pub url: Option<String>,
    pub description: String,
    pub severity: Option<String>,
    pub fixed_versions: Vec<String>,
}

#[derive(Deserialize)]
struct OsvDetail {
    #[serde(default)]
    details: String,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: OsvDatabase,
}
#[derive(Default, Deserialize)]
struct OsvDatabase {
    severity: Option<String>,
}
#[derive(Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}
#[derive(Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
    purl: Option<String>,
}
#[derive(Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}
#[derive(Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}
#[derive(Deserialize)]
struct GhsaDetail {
    ghsa_id: String,
    #[serde(default)]
    description: String,
    severity: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<GhsaVulnerability>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum GhsaResponse {
    Record(GhsaDetail),
    Page(Vec<GhsaDetail>),
}
#[derive(Deserialize)]
struct GhsaVulnerability {
    package: GhsaPackage,
    first_patched_version: Option<String>,
}
#[derive(Deserialize)]
struct GhsaPackage {
    name: String,
    ecosystem: String,
}

fn matches_package(instance: &Instance, name: &str, ecosystem: &str) -> bool {
    let Some(value) = &instance.purl else {
        return false;
    };
    let Ok(purl) = value.parse::<packageurl::PackageUrl<'_>>() else {
        return false;
    };
    let expected_name = match purl.namespace() {
        Some(namespace) => format!("{namespace}/{}", purl.name()),
        None => purl.name().to_owned(),
    };
    let registry = match purl.ty() {
        "cargo" => "crates.io",
        "composer" => "Packagist",
        "npm" => "npm",
        _ => return false,
    };
    name == expected_name
        && (ecosystem.eq_ignore_ascii_case(registry)
            || purl.ty() == "composer" && ecosystem == "composer"
            || purl.ty() == "cargo" && ecosystem == "rust")
}

pub(super) fn read(
    claim: &crate::model::Claim,
    instances: &[Instance],
    store: &Store,
) -> Result<Option<AdvisoryDetail>> {
    if !matches!(claim.source.as_str(), "osv" | "ghsa") {
        return Ok(None);
    }
    let bytes = crate::read_limited(
        &store
            .directory
            .join("evidence")
            .join(&claim.evidence.sha256),
        32 * 1024 * 1024,
    )?;
    anyhow::ensure!(
        crate::digest(&bytes) == claim.evidence.sha256,
        "advisory evidence integrity failed"
    );
    let mut fixed_versions = Vec::new();
    let (description, severity) = if claim.source == "osv" {
        let detail: OsvDetail = serde_json::from_slice(&bytes)?;
        for affected in detail.affected {
            let matches = instances.iter().any(|instance| {
                instance.id == claim.instance_id
                    && match &affected.package.purl {
                        Some(purl) => instance.purl.as_ref() == Some(purl),
                        None => matches_package(
                            instance,
                            &affected.package.name,
                            &affected.package.ecosystem,
                        ),
                    }
            });
            if matches {
                for range in affected.ranges {
                    fixed_versions.extend(range.events.into_iter().filter_map(|event| event.fixed));
                }
            }
        }
        (detail.details, detail.database_specific.severity)
    } else {
        let response: GhsaResponse = serde_json::from_slice(&bytes)?;
        let detail = match response {
            GhsaResponse::Record(detail) if detail.ghsa_id == claim.id => detail,
            GhsaResponse::Page(records) => records
                .into_iter()
                .find(|detail| detail.ghsa_id == claim.id)
                .ok_or_else(|| anyhow::anyhow!("advisory absent from recorded GHSA page"))?,
            _ => anyhow::bail!("recorded GHSA id mismatch"),
        };
        for vulnerability in detail.vulnerabilities {
            if instances.iter().any(|instance| {
                instance.id == claim.instance_id
                    && matches_package(
                        instance,
                        &vulnerability.package.name,
                        &vulnerability.package.ecosystem,
                    )
            }) {
                fixed_versions.extend(vulnerability.first_patched_version);
            }
        }
        (detail.description, detail.severity)
    };
    fixed_versions.sort();
    fixed_versions.dedup();
    Ok(Some(AdvisoryDetail {
        source: claim.source.clone(),
        advisory_id: claim.id.clone(),
        url: claim.evidence.url.clone(),
        description: description.chars().take(12_000).collect(),
        severity,
        fixed_versions,
    }))
}
