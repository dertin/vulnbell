use super::NotApplicableReason;
use crate::model::SourceFacts;
use anyhow::{Context, Result, bail};

#[cfg(test)]
thread_local! {
    static CONTENT_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn content_verifications() -> usize {
    CONTENT_VERIFICATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(super) fn reset_content_verifications() {
    CONTENT_VERIFICATIONS.with(|count| count.set(0));
}

pub(crate) fn verify_scope_evidence(
    artifact: &super::ArtifactEvidence,
    case: &crate::model::Case,
    store: &crate::store::Store,
) -> Result<()> {
    let instance = case
        .instances
        .iter()
        .find(|instance| instance.id == artifact.instance_id)
        .context("artifact instance is not in the case")?;
    let Some(installed) = artifact.installed_wheel.as_ref() else {
        if instance.origin == crate::model::Origin::ObservedArtifact {
            return Ok(());
        }
        bail!("a lockfile or a note alone does not establish which artifact was installed");
    };
    if !installed.scope_complete {
        bail!("installed wheel does not cover every in-scope build for this instance");
    }
    let note = case
        .evidence
        .iter()
        .find(|evidence| {
            evidence.id == installed.scope_evidence_id && evidence.source == "local_impact_evidence"
        })
        .context("installed wheel needs a registered note describing the assessed build scope")?;
    if !store.evidence_exists(note)? {
        bail!("installed wheel scope evidence is unavailable or corrupt");
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&note.sha256),
        64 * 1024,
    )?;
    let text =
        std::str::from_utf8(&bytes).context("installed wheel scope evidence must be UTF-8")?;
    if text.trim().len() < 20 || text.contains('\0') {
        bail!("installed wheel scope evidence must describe the reviewed build");
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) enum VerifiedArtifact {
    Observed,
    InstalledWheel(std::collections::HashSet<String>),
}

pub(crate) fn verify_artifact_content(
    artifact: &super::ArtifactEvidence,
    snapshot: &crate::model::Snapshot,
    instance_ids: &[String],
    store: &crate::store::Store,
) -> Result<VerifiedArtifact> {
    #[cfg(test)]
    CONTENT_VERIFICATIONS.with(|count| count.set(count.get() + 1));
    verify_artifact(artifact, snapshot, instance_ids, store)?;
    verify_content_after_artifact_verified(artifact, snapshot, instance_ids, store)
}

pub(crate) fn verify_content_after_artifact_verified(
    artifact: &super::ArtifactEvidence,
    snapshot: &crate::model::Snapshot,
    instance_ids: &[String],
    store: &crate::store::Store,
) -> Result<VerifiedArtifact> {
    if let Some(installed) = &artifact.installed_wheel {
        let roots = super::wheel::verify_content(artifact, installed, snapshot, store)?;
        verify_artifact(artifact, snapshot, instance_ids, store)?;
        Ok(VerifiedArtifact::InstalledWheel(roots))
    } else if !snapshot.instances.iter().any(|instance| {
        instance.id == artifact.instance_id
            && instance.origin == crate::model::Origin::ObservedArtifact
    }) {
        bail!("retraction requires an observed artifact or a verified installed wheel");
    } else {
        Ok(VerifiedArtifact::Observed)
    }
}

pub(crate) fn verify_artifact_scope(
    artifact: &super::ArtifactEvidence,
    snapshot: &crate::model::Snapshot,
    verified: &VerifiedArtifact,
) -> Result<()> {
    match (&artifact.installed_wheel, verified) {
        (Some(installed), VerifiedArtifact::InstalledWheel(roots)) => {
            super::wheel::verify_scope(artifact, installed, snapshot, roots)
        }
        (None, VerifiedArtifact::Observed) => Ok(()),
        _ => bail!("artifact scope does not match the verified installation"),
    }
}

pub(crate) fn verify_artifact(
    artifact: &super::ArtifactEvidence,
    snapshot: &crate::model::Snapshot,
    instance_ids: &[String],
    store: &crate::store::Store,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    if artifact.path.is_empty()
        || artifact.path.len() > 4096
        || !instance_ids.contains(&artifact.instance_id)
        || artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("artifact evidence must identify a reviewed instance and a SHA-256");
    }
    let root = snapshot
        .codebase_revisions
        .get(artifact.codebase)
        .context("artifact codebase is outside the monitor")?;
    let instance = snapshot
        .instances
        .iter()
        .find(|instance| instance.id == artifact.instance_id)
        .context("artifact instance is not in the snapshot")?;
    if instance.resolved_version.is_none()
        || instance
            .provenance
            .codebase
            .as_deref()
            .is_some_and(|codebase| codebase != root.codebase)
    {
        bail!("artifact evidence must belong to the resolved instance and its codebase");
    }
    let observed = instance.origin == crate::model::Origin::ObservedArtifact
        && instance.provenance.sha256 == artifact.sha256;
    let verified_wheel = artifact.path.to_ascii_lowercase().ends_with(".whl")
        && instance.identity_evidence.iter().any(|evidence| {
            if !matches!(evidence.source.as_str(), "registry_hash_match" | "registry")
                || !store.evidence_exists(evidence).unwrap_or(false)
                || !evidence
                    .url
                    .as_deref()
                    .and_then(|value| url::Url::parse(value).ok())
                    .is_some_and(|url| {
                        url.scheme() == "https"
                            && url.host_str() == Some("pypi.org")
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.port().is_none()
                            && url.query().is_none()
                            && url.fragment().is_none()
                    })
            {
                return false;
            }
            let path = store.directory.join("evidence").join(&evidence.sha256);
            crate::read_limited(&path, 32 * 1024 * 1024)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|document| {
                    let purl: packageurl::PackageUrl<'_> =
                        instance.purl.as_deref()?.parse().ok()?;
                    if purl.ty() != "pypi"
                        || purl.namespace().is_some()
                        || crate::identity::normalize_pypi(
                            document.pointer("/info/name")?.as_str()?,
                        ) != crate::identity::normalize_pypi(purl.name())
                        || document
                            .pointer("/info/version")?
                            .as_str()?
                            .parse::<pep508_rs::pep440_rs::Version>()
                            .ok()?
                            != instance
                                .resolved_version
                                .as_deref()?
                                .parse::<pep508_rs::pep440_rs::Version>()
                                .ok()?
                    {
                        return None;
                    }
                    document
                        .get("urls")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                })
                .is_some_and(|urls| {
                    urls.iter().any(|file| {
                        file.pointer("/digests/sha256")
                            .and_then(serde_json::Value::as_str)
                            == Some(&artifact.sha256)
                    })
                })
        })
        && instance.python_lock.as_ref().is_none_or(|lock| {
            lock.source_eligible && lock.sha256.iter().any(|hash| hash == &artifact.sha256)
        });
    if !observed && !verified_wheel {
        bail!("artifact digest is not bound to the monitored instance");
    }
    let artifact_root = artifact_root(artifact, snapshot, store)?;
    crate::discovery::checked_path(&artifact_root, &artifact.path)?;
    let mut file = crate::discovery::open_file(&artifact_root, &artifact.path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > 512 * 1024 * 1024 {
        bail!("artifact evidence must be a regular file within the 512 MiB limit");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > before.len() {
            bail!("artifact changed during verification");
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if total != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || hex::encode(digest.finalize()) != artifact.sha256
    {
        bail!("artifact evidence does not match the monitored file");
    }
    Ok(())
}

pub(super) fn artifact_root(
    artifact: &super::ArtifactEvidence,
    snapshot: &crate::model::Snapshot,
    store: &crate::store::Store,
) -> Result<String> {
    match artifact.location {
        super::ArtifactLocation::Codebase => Ok(snapshot
            .codebase_revisions
            .get(artifact.codebase)
            .context("artifact codebase is outside the monitor")?
            .codebase
            .clone()),
        super::ArtifactLocation::MonitorWorkspace => {
            let profile = store
                .meta("profile_path")?
                .context("monitor profile path is unavailable")?;
            let path = std::path::Path::new(&profile).canonicalize()?;
            Ok(path
                .parent()
                .context("monitor profile has no directory")?
                .to_str()
                .context("monitor path is not UTF-8")?
                .to_owned())
        }
    }
}

pub(crate) fn validate_source_facts(
    facts: &SourceFacts,
    reason: Option<NotApplicableReason>,
) -> Result<()> {
    if facts.identifiers.len() > 32
        || facts.identifiers.iter().any(|identifier| {
            identifier.len() > 64
                || !identifier.contains('-')
                || !identifier
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        bail!(
            "source_facts.identifiers takes up to 32 advisory IDs such as CVE-2026-1234 or GHSA-xxxx-xxxx-xxxx"
        );
    }
    let texts = [
        &facts.affected_versions,
        &facts.fixed_in,
        &facts.fix_reference,
        &facts.required_feature,
    ];
    if texts
        .iter()
        .any(|text| text.len() > 500 || text.chars().any(char::is_control))
    {
        bail!("source_facts text fields take one line of up to 500 characters");
    }
    match reason {
        Some(NotApplicableReason::FixedInMonitoredVersion) if facts.fixed_in.trim().is_empty() => {
            bail!("fixed_in_monitored_version requires source_facts.fixed_in as the item states it")
        }
        Some(NotApplicableReason::AffectsOtherVersion)
            if facts.affected_versions.trim().is_empty() =>
        {
            bail!(
                "affects_other_version requires source_facts.affected_versions as the item states it"
            )
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn artifact_evidence_requires_the_monitored_digest_and_instance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("installed.bin"), b"synthetic artifact").unwrap();
        let mut instance = crate::model::Instance::declared(&crate::profile::Component {
            reference: "example".into(),
            version: Some("1.0".into()),
            usage: Default::default(),
            upstream: None,
            feeds: Vec::new(),
        });
        instance.origin = crate::model::Origin::ObservedArtifact;
        instance.provenance.sha256 = crate::digest(b"synthetic artifact");
        let project = uuid::Uuid::new_v4().to_string();
        let store = crate::store::Store::open(&project).unwrap();
        let snapshot = crate::model::Snapshot {
            schema_version: 1,
            id: "snapshot".into(),
            project_id: project.clone(),
            profile_sha256: "profile".into(),
            started_at: crate::now(),
            finished_at: crate::now(),
            codebase_revisions: vec![crate::codebase_revision::capture_path(dir.path())],
            instances: vec![instance.clone()],
            coverage: Vec::new(),
            cases: Vec::new(),
            partial: false,
            alert_status: "local".into(),
        };
        let mut evidence = crate::research::ArtifactEvidence {
            instance_id: instance.id.clone(),
            codebase: 0,
            location: crate::research::ArtifactLocation::Codebase,
            path: "installed.bin".into(),
            sha256: instance.provenance.sha256.clone(),
            installed_wheel: None,
        };
        assert!(
            verify_artifact(
                &evidence,
                &snapshot,
                std::slice::from_ref(&instance.id),
                &store
            )
            .is_ok()
        );
        evidence.sha256 = crate::digest(b"different artifact");
        assert!(
            verify_artifact(
                &evidence,
                &snapshot,
                std::slice::from_ref(&instance.id),
                &store
            )
            .is_err()
        );
        evidence.sha256 = instance.provenance.sha256.clone();
        evidence.path = "../outside".into();
        assert!(
            verify_artifact(
                &evidence,
                &snapshot,
                std::slice::from_ref(&instance.id),
                &store
            )
            .is_err()
        );
        evidence.path = "installed.bin".into();
        let event = crate::research::ResearchEvent {
            upstream: "https://github.com/example/project".into(),
            codebase_revisions: Vec::new(),
            instance_ids: vec![instance.id.clone()],
            reviewed_instance_ids: vec![instance.id.clone()],
            provider: "github".into(),
            external_id: "example/project#1".into(),
            kind: crate::research::EventKind::PullRequest,
            url: "https://github.com/example/project/pull/1".into(),
            title: "Fixture".into(),
            excerpt: "Fixture".into(),
            updated_at: crate::now(),
            assessment: crate::research::Assessment::NotApplicable,
            not_applicable_reason: Some(crate::research::NotApplicableReason::ComponentNotInBuild),
            artifact_evidence: Some(evidence),
            rationale: "The module is absent from the observed artifact.".into(),
            source_facts: Default::default(),
        };
        let recorded = store
            .record_evidence(
                &serde_json::to_vec(&event).unwrap(),
                "agent_retraction_assessment",
                Some(event.url.clone()),
                crate::model::EvidenceKind::Context,
            )
            .unwrap();
        let observation = store
            .record_evidence(
                b"Synthetic upstream observation",
                "agent_upstream_observation",
                Some(event.url.clone()),
                crate::model::EvidenceKind::Context,
            )
            .unwrap();
        let case = crate::model::Case {
            schema_version: 1,
            case_id: "SIG-fixture".into(),
            project_id: project.clone(),
            snapshot_id: snapshot.id.clone(),
            codebase_revisions: snapshot.codebase_revisions.clone(),
            instances: vec![instance.clone()],
            claims: Vec::new(),
            upstream_events: vec![crate::model::UpstreamEvent {
                provider: event.provider.clone(),
                kind: "pull_request".into(),
                id: event.external_id.clone(),
                url: event.url.clone(),
                title: event.title.clone(),
                updated_at: Some(event.updated_at.clone()),
                sha256: observation.sha256.clone(),
                source_facts: Default::default(),
            }],
            evidence: vec![observation, recorded],
            coverage: Vec::new(),
            applicability: crate::model::Applicability::Unknown,
            verification: crate::model::Verification::Inconclusive,
            decision: crate::model::Decision::Retracted,
            facts_sha256: "fixture".into(),
            open_questions: Vec::new(),
            suggested_search_queries: Vec::new(),
            sandbox: crate::model::SandboxAvailability {
                available: false,
                reason: "fixture".into(),
            },
            updated_at: crate::now(),
        };
        assert!(super::super::retraction_valid(
            &case,
            &snapshot.instances,
            &snapshot.codebase_revisions,
            &store
        ));
        std::fs::write(dir.path().join("installed.bin"), b"changed artifact").unwrap();
        assert!(!super::super::retraction_valid(
            &case,
            &snapshot.instances,
            &snapshot.codebase_revisions,
            &store
        ));
        fs::write(dir.path().join("example.whl"), b"observed artifact").unwrap();
        let digest = crate::digest(b"observed artifact");
        let registry = store
            .record_evidence(
                serde_json::json!({"info":{"name":"example","version":"1.0"},"urls":[{"digests":{"sha256":digest}}]})
                    .to_string()
                    .as_bytes(),
                "registry_hash_match",
                Some("https://pypi.org/pypi/example/1.0/json".into()),
                crate::model::EvidenceKind::Identity,
            )
            .unwrap();
        let mut locked = instance.clone();
        locked.origin = crate::model::Origin::Locked;
        locked.purl = Some("pkg:pypi/example".into());
        locked.identity_evidence.push(registry);
        locked.python_lock = Some(crate::model::PythonLock {
            sha256: vec![digest.clone()],
            source_eligible: true,
            via: Vec::new(),
            via_complete: false,
            direct_source: None,
        });
        let mut locked_snapshot = snapshot.clone();
        locked_snapshot.instances = vec![locked.clone()];
        let mut locked_case = case.clone();
        locked_case.instances = vec![locked];
        let wheel = crate::research::ArtifactEvidence {
            instance_id: instance.id.clone(),
            codebase: 0,
            location: crate::research::ArtifactLocation::Codebase,
            path: "example.whl".into(),
            sha256: digest.clone(),
            installed_wheel: None,
        };
        assert!(
            verify_artifact(
                &wheel,
                &locked_snapshot,
                std::slice::from_ref(&instance.id),
                &store
            )
            .is_ok()
        );
        assert!(verify_scope_evidence(&wheel, &locked_case, &store).is_err());
        let note = store
            .record_evidence(
                format!("Installed version 1.0 from example.whl with sha256 {digest}").as_bytes(),
                "local_impact_evidence",
                None,
                crate::model::EvidenceKind::Context,
            )
            .unwrap();
        locked_case.evidence.push(note);
        assert!(verify_scope_evidence(&wheel, &locked_case, &store).is_err());
        locked_case.instances[0].origin = crate::model::Origin::Deployed;
        assert!(verify_scope_evidence(&wheel, &locked_case, &store).is_err());
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }
}
