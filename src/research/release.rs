//! Exact-version publication dates from registries or explicit product repositories. A date is a research boundary,
//! never evidence that older vulnerabilities cannot affect the version.
use crate::{
    model::{Coverage, CoverageState, EvidenceKind, Instance, ReleaseDate},
    network::Http,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde_json::Value;

fn request(instance: &Instance) -> Result<(String, String, String)> {
    let purl = instance
        .purl
        .as_deref()
        .context("package identity unavailable")?
        .parse::<packageurl::PackageUrl<'_>>()?;
    let version = instance
        .resolved_version
        .as_deref()
        .context("exact version unavailable")?;
    let name = match purl.namespace() {
        Some(namespace) => format!("{namespace}/{}", purl.name()),
        None => purl.name().to_owned(),
    };
    let encode = crate::sources::encode;
    let url = match purl.ty() {
        "cargo" if purl.namespace().is_none() => format!(
            "https://crates.io/api/v1/crates/{}/{}",
            encode(&name),
            encode(version)
        ),
        "npm" => format!("https://registry.npmjs.org/{}", encode(&name)),
        "pypi" if purl.namespace().is_none() => format!(
            "https://pypi.org/pypi/{}/{}/json",
            encode(&name),
            encode(version)
        ),
        _ => bail!("release date source unsupported for this identity"),
    };
    Ok((url, name, purl.ty().to_owned()))
}

fn published_at(ecosystem: &str, name: &str, version: &str, body: &[u8]) -> Result<String> {
    let document: Value = serde_json::from_slice(body)?;
    let timestamp = match ecosystem {
        "cargo"
            if document["version"]["crate"].as_str() == Some(name)
                && document["version"]["num"].as_str() == Some(version) =>
        {
            document["version"]["created_at"]
                .as_str()
                .map(str::to_owned)
        }
        "npm"
            if document["name"].as_str() == Some(name)
                && document["versions"][version]["version"].as_str() == Some(version) =>
        {
            document["time"][version].as_str().map(str::to_owned)
        }
        "pypi"
            if document["info"]["name"].as_str().is_some_and(|n| {
                n.eq_ignore_ascii_case(name)
                    || n.replace(['_', '.'], "-")
                        .eq_ignore_ascii_case(&name.replace(['_', '.'], "-"))
            }) && document["info"]["version"].as_str() == Some(version) =>
        {
            document["urls"].as_array().and_then(|files| {
                files
                    .iter()
                    .filter_map(|file| file["upload_time_iso_8601"].as_str())
                    .filter_map(|value| DateTime::parse_from_rfc3339(value).ok())
                    .min()
                    .map(|value| value.to_rfc3339())
            })
        }
        "github"
            if document["tag_name"]
                .as_str()
                .is_some_and(|tag| tag == version || tag == format!("v{version}"))
                && document["draft"].as_bool() == Some(false) =>
        {
            document["published_at"].as_str().map(str::to_owned)
        }
        _ => None,
    }
    .context("registry response does not identify the exact version or publication date")?;
    let parsed = DateTime::parse_from_rfc3339(&timestamp)?;
    if parsed > Utc::now() {
        bail!("registry publication date is in the future");
    }
    Ok(parsed.to_rfc3339())
}

fn registry_release(instance: &Instance, http: &mut Http<'_>) -> Result<ReleaseDate> {
    let (url, name, ecosystem) = request(instance)?;
    let version = instance
        .resolved_version
        .as_deref()
        .context("exact version unavailable")?;
    let response = http.get(&url)?;
    if response.truncated {
        bail!("registry response was truncated");
    }
    let date = published_at(&ecosystem, &name, version, &response.body)?;
    let evidence = http.store.record_evidence(
        &response.body,
        "release_registry",
        Some(response.url),
        EvidenceKind::Context,
    )?;
    Ok(ReleaseDate {
        version: version.to_owned(),
        published_at: date,
        evidence,
    })
}

fn github_release(instance: &Instance, http: &mut Http<'_>) -> Result<ReleaseDate> {
    let upstream = instance
        .upstream
        .as_deref()
        .context("explicit upstream unavailable")?;
    let url = url::Url::parse(upstream)?;
    let parts: Vec<_> = url
        .path_segments()
        .context("invalid upstream")?
        .filter(|part| !part.is_empty())
        .collect();
    if url.host_str() != Some("github.com") || parts.len() != 2 {
        bail!("explicit upstream is not a GitHub repository");
    }
    let version = instance
        .resolved_version
        .as_deref()
        .context("exact version unavailable")?;
    let tags = [format!("v{version}"), version.to_owned()];
    let mut found = None;
    for tag in &tags {
        let api = format!(
            "https://api.github.com/repos/{}/{}/releases/tags/{}",
            parts[0],
            parts[1].trim_end_matches(".git"),
            crate::sources::encode(tag)
        );
        let response = match http.get(&api) {
            Ok(response) => response,
            Err(error) if error.to_string().contains("HTTP 404") => continue,
            Err(error) => return Err(error),
        };
        if response.truncated {
            bail!("release response was truncated");
        }
        let date = published_at("github", "", version, &response.body)?;
        if found.is_some() {
            bail!("multiple GitHub release tags match this version; choose a source explicitly");
        }
        found = Some((date, response));
    }
    let (date, response) = found.context("no exact version release found")?;
    let evidence = http.store.record_evidence(
        &response.body,
        "release_github",
        Some(response.url),
        EvidenceKind::Context,
    )?;
    Ok(ReleaseDate {
        version: version.to_owned(),
        published_at: date,
        evidence,
    })
}

pub fn acquire(instance: &mut Instance, http: &mut Http<'_>, declared_upstream: bool) -> Coverage {
    let result = match registry_release(instance, http) {
        Ok(release) => Ok(release),
        Err(registry_error) if declared_upstream => github_release(instance, http)
            .with_context(|| format!("registry release lookup failed: {registry_error}")),
        Err(error) => Err(error),
    };
    match result {
        Ok(release) => {
            instance.release = Some(release);
            Coverage::new(
                "release_window",
                &instance.id,
                CoverageState::Checked,
                "exact version publication date acquired; earlier issues are outside this window, not proven safe",
            )
        }
        Err(error) => Coverage::new(
            "release_window",
            &instance.id,
            CoverageState::Partial,
            format!("exact release date unavailable; initial fallback window applies: {error:#}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::published_at;
    #[test]
    fn exact_identity_and_time_are_required() {
        let cargo =
            br#"{"version":{"crate":"demo","num":"1.2.3","created_at":"2026-01-01T00:00:00Z"}}"#;
        assert!(published_at("cargo", "demo", "1.2.3", cargo).is_ok());
        assert!(published_at("cargo", "demo", "1.2.4", cargo).is_err());
        let npm = br#"{"name":"demo","versions":{"1.0.0":{"version":"1.0.0"}},"time":{"1.0.0":"2026-02-01T00:00:00Z"}}"#;
        assert!(published_at("npm", "demo", "1.0.0", npm).is_ok());
        assert!(published_at("npm", "other", "1.0.0", npm).is_err());
        let github =
            br#"{"tag_name":"v1.2.3","draft":false,"published_at":"2026-01-01T00:00:00Z"}"#;
        assert!(published_at("github", "", "1.2.3", github).is_ok());
        assert!(published_at("github", "", "1.2.4", github).is_err());
        let pypi = br#"{"info":{"name":"Demo_pkg","version":"1.0"},"urls":[{"upload_time_iso_8601":"2026-02-03T00:00:00Z"},{"upload_time_iso_8601":"2026-02-01T00:00:00Z"}]}"#;
        assert!(
            published_at("pypi", "demo-pkg", "1.0", pypi)
                .unwrap()
                .starts_with("2026-02-01")
        );
    }
}
