use crate::{
    model::{Case, EvidenceKind, Verification},
    profile::SandboxLimits,
    store::Store,
};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_TEST_INPUTS: usize = 20;

/// Planning limits only; the runtime's effective policy is checked during verification.
pub fn capabilities(limits: SandboxLimits) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "workspace_stage": {"max_files": staging::MAX_STAGED_FILES, "max_archive_bytes": staging::MAX_ARCHIVE_BYTES, "whole_directory": false},
        "test": {"max_inputs": MAX_TEST_INPUTS, "limits": limits, "guest_disk_mib": 2048},
        "profile_caps": {"max_input_file_mib": SandboxLimits::CAP_INPUT_FILE_MIB, "max_inputs_mib": SandboxLimits::CAP_INPUTS_MIB, "max_memory_mib": SandboxLimits::CAP_MEMORY_MIB, "max_timeout_seconds": SandboxLimits::CAP_TIMEOUT_SECONDS},
        "required_network_policy": "deny_ingress_and_egress",
        "runtime_policy_checked_during_verify": true,
        "explicit_authorization_required": true
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestSpec {
    pub schema_version: u32,
    pub instance_id: String,
    pub artifact_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<TestContext>,
    pub script: String,
    pub oracle: Oracle,
    #[serde(default)]
    pub control: Option<ControlSpec>,
    #[serde(default)]
    pub inputs: Vec<TestInput>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_memory")]
    pub memory_mib: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestContext {
    pub mode: TestMode,
    pub description: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TestMode {
    WorkspaceCopy,
    ArtifactReproducer,
}
/// Why a sandbox check the case needs cannot run. Missing deployment facts are not a kind: the
/// sandbox cannot establish them, so they never require a check.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    /// The advisory or report does not disclose enough to build an oracle.
    DetailsUndisclosed,
    /// The exact artifact cannot be obtained from an official source with a checksum.
    ArtifactUnavailable,
    /// The artifact or workload exceeds the profile's sandbox limits or their caps.
    SandboxLimits,
    /// Microsandbox cannot run on this host.
    RuntimeUnavailable,
    /// The operator declined to authorize the test.
    AuthorizationDeclined,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationBlocker {
    pub schema_version: u32,
    pub case_id: String,
    pub facts_sha256: String,
    pub instance_id: String,
    /// Absent for failed runs and for blockers recorded before kinds existed; neither settles a
    /// needed check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<BlockerKind>,
    /// A later reviewed correction supersedes an earlier blocker for these same case facts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cleared: bool,
    pub reason: String,
}

/// Without `instance_id` the blocker applies to every instance of the current case.
pub fn record_blocker(
    store: &mut Store,
    id: &str,
    instance_id: Option<&str>,
    kind: BlockerKind,
    reason: &str,
) -> Result<Case> {
    let _lock = store.lock()?;
    let mut case = store.case(id)?;
    let instance_ids: Vec<String> = match instance_id {
        Some(instance_id) => vec![instance_id.to_owned()],
        None => case
            .instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect(),
    };
    for instance_id in &instance_ids {
        append_blocker(&mut case, store, instance_id, Some(kind), false, reason)?;
    }
    store.save_case(&case)?;
    Ok(case)
}

/// Supersede a mistaken or no-longer-valid blocker without deleting its evidence history.
pub fn clear_blocker(
    store: &mut Store,
    id: &str,
    instance_id: Option<&str>,
    reason: &str,
) -> Result<Case> {
    let _lock = store.lock()?;
    let mut case = store.case(id)?;
    let ids: Vec<String> = match instance_id {
        Some(id) => vec![id.to_owned()],
        None => case
            .instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect(),
    };
    for id in &ids {
        append_blocker(&mut case, store, id, None, true, reason)?;
    }
    store.save_case(&case)?;
    Ok(case)
}

fn append_blocker(
    case: &mut Case,
    store: &Store,
    instance_id: &str,
    kind: Option<BlockerKind>,
    cleared: bool,
    reason: &str,
) -> Result<()> {
    if reason.trim().is_empty()
        || reason.len() > 2000
        || !case
            .instances
            .iter()
            .any(|instance| instance.id == instance_id)
    {
        bail!("validation blocker requires a current instance and a reason of 1..2000 bytes");
    }
    let blocker = VerificationBlocker {
        schema_version: 1,
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        instance_id: instance_id.into(),
        kind,
        cleared,
        reason: reason.into(),
    };
    let evidence = store.record_evidence(
        &serde_json::to_vec(&blocker)?,
        "local_validation_blocker",
        None,
        EvidenceKind::Context,
    )?;
    case.evidence.push(evidence);
    case.updated_at = crate::now();
    Ok(())
}
fn default_timeout() -> u64 {
    30
}
fn default_memory() -> u32 {
    256
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oracle {
    pub stdout_contains: String,
    pub expected_exit: i32,
    #[serde(default)]
    pub purpose: OraclePurpose,
}
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OraclePurpose {
    #[default]
    Reproduction,
    PositiveNonApplicability,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlSpec {
    pub artifact_version: String,
    pub inputs: Vec<TestInput>,
    pub stdout_contains: String,
    pub expected_exit: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ControlObservation {
    pub artifact_version: String,
    pub input_sha256: Vec<String>,
    pub output_sha256: String,
    pub oracle_matched: bool,
    pub policy_verified: bool,
}
struct GuestObservation {
    process: crate::process::ProcessResult,
    staging_sha256: String,
    policy_sha256: String,
    policy_ok: bool,
    completed: bool,
    policy_evidence: crate::model::Evidence,
    status_evidence: crate::model::Evidence,
    oracle_matches: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestInput {
    pub path: PathBuf,
    pub name: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub schema_version: u32,
    pub runtime_executable: PathBuf,
    pub runtime_sha256: String,
    pub runtime_version: String,
    pub image_reference: String,
    pub image_manifest_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub schema_version: u32,
    pub project_id: String,
    pub case_id: String,
    pub facts_sha256: String,
    pub instance_id: String,
    pub artifact_version: String,
    pub runtime: String,
    pub runtime_version: String,
    pub runtime_sha256: String,
    pub test_sha256: String,
    pub image_reference: String,
    pub image_manifest_digest: String,
    pub staging_sha256: String,
    pub policy_sha256: String,
    pub input_sha256: Vec<String>,
    pub oracle: Oracle,
    pub control: Option<ControlObservation>,
    pub network_devices: String,
    pub host_mounts: Vec<String>,
    pub memory_mib: u32,
    pub cpu_count: u32,
    pub timeout_seconds: u64,
    pub output_sha256: String,
    pub execution_status_sha256: String,
    pub exit_code: Option<i32>,
    pub execution_complete: bool,
    pub timed_out: bool,
    pub verification: Verification,
    pub observed_at: String,
}

pub fn read_attestation(
    case: &Case,
    store: &Store,
    evidence: &crate::model::Evidence,
) -> Result<Attestation> {
    if evidence.kind != EvidenceKind::Attestation || !store.evidence_exists(evidence)? {
        bail!("attestation integrity failed");
    }
    let bytes = crate::read_limited(
        &store.directory.join("evidence").join(&evidence.sha256),
        1024 * 1024,
    )?;
    let attestation: Attestation = serde_json::from_slice(&bytes)?;
    if attestation.schema_version != 2
        || attestation.runtime != "microsandbox"
        || attestation.project_id != case.project_id
        || attestation.case_id != case.case_id
        || attestation.facts_sha256 != case.facts_sha256
        || !case.instances.iter().any(|instance| {
            instance.id == attestation.instance_id
                && instance.resolved_version.as_deref() == Some(&attestation.artifact_version)
        })
    {
        bail!("stale or mismatched attestation");
    }
    let mut hashes = vec![
        &attestation.output_sha256,
        &attestation.policy_sha256,
        &attestation.execution_status_sha256,
    ];
    if let Some(control) = &attestation.control {
        hashes.push(&control.output_sha256);
    }
    for hash in hashes {
        let linked = case
            .evidence
            .iter()
            .find(|item| item.sha256 == *hash)
            .context("missing runtime evidence")?;
        if !store.evidence_exists(linked)? {
            bail!("runtime evidence integrity failed");
        }
    }
    if matches!(
        attestation.verification,
        Verification::LabReproduced | Verification::Disproven
    ) && (!attestation.execution_complete
        || attestation.timed_out
        || attestation.exit_code != Some(attestation.oracle.expected_exit))
    {
        bail!("successful verdict contradicts job outcome");
    }
    if attestation.verification == Verification::Disproven
        && !attestation
            .control
            .as_ref()
            .is_some_and(|control| control.oracle_matched && control.policy_verified)
    {
        bail!("non-applicability lacks a positive control");
    }
    Ok(attestation)
}

pub fn verify(
    store: &mut Store,
    id: &str,
    spec_path: &Path,
    authorized: bool,
    limits: &SandboxLimits,
) -> Result<Case> {
    if !authorized {
        bail!(
            "active verification requires explicit --authorize after reviewing the test and inputs"
        );
    }
    let _lock = store.lock()?;
    let mut case = store.case(id)?;
    let test_bytes = crate::read_limited(spec_path, 1024 * 1024)?;
    let test: TestSpec = crate::parse_yaml(&test_bytes)?;
    if test.schema_version != 1
        || test.inputs.len() > MAX_TEST_INPUTS
        || test.script.len() > 65536
        || test.oracle.stdout_contains.is_empty()
        || !(0..=255).contains(&test.oracle.expected_exit)
    {
        bail!("invalid test version/oracle or more than 20 inputs");
    }
    if !(1..=limits.max_timeout_seconds).contains(&test.timeout_seconds)
        || !(128..=limits.max_memory_mib).contains(&test.memory_mib)
    {
        bail!(
            "test requests timeout_seconds 1..{} and memory_mib 128..{} (profile sandbox limits)",
            limits.max_timeout_seconds,
            limits.max_memory_mib
        );
    }
    if let Some(context) = &test.context
        && (context.description.trim().is_empty() || context.description.len() > 2000)
    {
        bail!("test context requires a description of 1..2000 bytes");
    }
    if !case.instances.iter().any(|instance| {
        instance.id == test.instance_id
            && instance.resolved_version.as_deref() == Some(&test.artifact_version)
    }) {
        bail!("test must target an exact instance and artifact version from this case");
    }
    let test_evidence = store.record_evidence(
        &test_bytes,
        "microsandbox_test",
        None,
        EvidenceKind::Context,
    )?;
    case.evidence.push(test_evidence);
    if !availability().available {
        case.verification = Verification::Inconclusive;
        if case.decision == crate::model::Decision::Dismissed {
            case.decision = crate::model::Decision::Review;
            case.applicability = crate::model::Applicability::Unknown;
        }
        case.sandbox = availability();
        let reason = case.sandbox.reason.clone();
        append_blocker(
            &mut case,
            store,
            &test.instance_id,
            Some(BlockerKind::RuntimeUnavailable),
            false,
            &reason,
        )?;
        case.updated_at = crate::now();
        store.save_case(&case)?;
        return Ok(case);
    }
    let image: Image = serde_json::from_slice(&crate::read_limited(&image_path(), 65536)?)?;
    validate_image(&image.image_reference)?;
    if image.schema_version != 2
        || crate::digest(&crate::read_limited(
            &image.runtime_executable,
            128 * 1024 * 1024,
        )?) != image.runtime_sha256
    {
        bail!(
            "Microsandbox runtime integrity failed; prepare again after reviewing the installation"
        );
    }
    let version = checked_runtime(&image.runtime_executable, &["--version"], 5)?;
    if String::from_utf8_lossy(&version).trim() != image.runtime_version {
        bail!("Microsandbox runtime version changed");
    }
    let input_root = spec_path
        .canonicalize()?
        .parent()
        .context("test directory missing")?
        .join("inputs");
    if test.oracle.purpose == OraclePurpose::PositiveNonApplicability {
        let control = test.control.as_ref().context("positive non-applicability requires a contrasting known-positive control with the same script")?;
        if test.inputs.is_empty()
            || control.inputs.is_empty()
            || control.inputs.len() > MAX_TEST_INPUTS
            || control.stdout_contains.is_empty()
            || control.artifact_version.is_empty()
            || !(0..=255).contains(&control.expected_exit)
            || control.stdout_contains == test.oracle.stdout_contains
            || control
                .inputs
                .iter()
                .map(|input| &input.sha256)
                .collect::<Vec<_>>()
                == test
                    .inputs
                    .iter()
                    .map(|input| &input.sha256)
                    .collect::<Vec<_>>()
        {
            bail!(
                "non-applicability control must use distinct checksummed artifacts and a contrasting observable result"
            );
        }
    }
    case.verification = Verification::Inconclusive;
    if case.decision == crate::model::Decision::Dismissed {
        case.decision = crate::model::Decision::Review;
        case.applicability = crate::model::Applicability::Unknown;
    }
    case.updated_at = crate::now();
    store.save_case(&case)?;
    let observation = match execute_guest(store, &image, &test, &input_root, limits) {
        Ok(observation) => observation,
        Err(error) => {
            // A failed run may come from the test itself, so it does not settle the check.
            append_blocker(
                &mut case,
                store,
                &test.instance_id,
                None,
                false,
                &error.to_string(),
            )?;
            store.save_case(&case)?;
            return Err(error);
        }
    };
    let process = observation.process;
    let policy_ok = observation.policy_ok;
    let oracle_matches = observation.oracle_matches;
    let mut verification =
        if observation.completed && !process.timed_out && policy_ok && oracle_matches {
            Verification::LabReproduced
        } else if observation.completed && policy_ok && !process.timed_out {
            Verification::NotReproduced
        } else {
            Verification::Inconclusive
        };
    let mut control_observation = None;
    if let Some(control) = &test.control {
        let mut control_test = test.clone();
        control_test.inputs = control.inputs.clone();
        control_test.oracle = Oracle {
            stdout_contains: control.stdout_contains.clone(),
            expected_exit: control.expected_exit,
            purpose: OraclePurpose::Reproduction,
        };
        control_test.control = None;
        let observed = execute_guest(store, &image, &control_test, &input_root, limits)?;
        let control_output = store.record_evidence(
            &observed.process.stdout,
            "microsandbox_control_output",
            None,
            EvidenceKind::Context,
        )?;
        let matched = observed.completed
            && !observed.process.timed_out
            && observed.policy_ok
            && observed.oracle_matches;
        control_observation = Some(ControlObservation {
            artifact_version: control.artifact_version.clone(),
            input_sha256: control
                .inputs
                .iter()
                .map(|input| input.sha256.clone())
                .collect(),
            output_sha256: control_output.sha256.clone(),
            oracle_matched: matched,
            policy_verified: observed.policy_ok,
        });
        case.evidence.extend([
            control_output,
            observed.policy_evidence,
            observed.status_evidence,
        ]);
        if test.oracle.purpose == OraclePurpose::PositiveNonApplicability {
            verification = if verification == Verification::LabReproduced && matched {
                Verification::Disproven
            } else {
                Verification::Inconclusive
            };
        }
    }
    let output_evidence = store.record_evidence(
        &process.stdout,
        "microsandbox_stdout",
        None,
        EvidenceKind::Context,
    )?;
    let attestation = Attestation {
        schema_version: 2,
        project_id: case.project_id.clone(),
        case_id: case.case_id.clone(),
        facts_sha256: case.facts_sha256.clone(),
        instance_id: test.instance_id.clone(),
        artifact_version: test.artifact_version.clone(),
        runtime: "microsandbox".into(),
        runtime_version: image.runtime_version,
        runtime_sha256: image.runtime_sha256,
        test_sha256: crate::digest(&test_bytes),
        image_reference: image.image_reference,
        image_manifest_digest: image.image_manifest_digest,
        staging_sha256: observation.staging_sha256,
        policy_sha256: observation.policy_sha256,
        input_sha256: test
            .inputs
            .iter()
            .map(|input| input.sha256.clone())
            .collect(),
        oracle: test.oracle,
        control: control_observation,
        network_devices: "runtime policy: deny all ingress/egress; device retained".into(),
        host_mounts: Vec::new(),
        memory_mib: test.memory_mib,
        cpu_count: 1,
        timeout_seconds: test.timeout_seconds,
        output_sha256: output_evidence.sha256.clone(),
        execution_status_sha256: observation.status_evidence.sha256.clone(),
        exit_code: process.exit_code,
        execution_complete: observation.completed,
        timed_out: process.timed_out,
        verification,
        observed_at: crate::now(),
    };
    let evidence = store.record_evidence(
        &serde_json::to_vec(&attestation)?,
        "microsandbox_runtime",
        None,
        EvidenceKind::Attestation,
    )?;
    case.evidence.extend([
        output_evidence,
        evidence,
        observation.policy_evidence,
        observation.status_evidence,
    ]);
    case.verification = verification;
    if case.decision == crate::model::Decision::Dismissed && verification != Verification::Disproven
    {
        case.decision = crate::model::Decision::Review;
        case.applicability = crate::model::Applicability::Unknown;
    }
    case.updated_at = crate::now();
    if verification == Verification::Inconclusive {
        let error = store.record_evidence(
            &process.stderr,
            "microsandbox_stderr",
            None,
            EvidenceKind::Context,
        )?;
        case.evidence.push(error);
    }
    store.save_case(&case)?;
    Ok(case)
}

mod runtime;
pub mod staging;
pub use runtime::{availability, image_path, prepare, prepare_image};
use runtime::{checked_runtime, execute_guest, validate_image};
