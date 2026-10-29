use super::{GuestObservation, Image, TestSpec};
use crate::{
    model::{EvidenceKind, SandboxAvailability},
    profile::SandboxLimits,
    store::Store,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const RUNTIME_VERSION: &str = "0.7.11";
const RUNTIME_RELEASE: &str =
    "https://github.com/superradcompany/microsandbox/releases/tag/v0.7.11";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f";
pub fn image_path() -> PathBuf {
    crate::store::data_root().join("sandbox/microsandbox.json")
}
fn runtime_home() -> PathBuf {
    crate::store::data_root().join("sandbox/msb")
}
pub fn availability() -> SandboxAvailability {
    let available = crate::read_limited(&image_path(), 65536)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Image>(&bytes).ok())
        .is_some_and(|image| image.schema_version == 2 && image.runtime_executable.is_file());
    SandboxAvailability {
        available,
        reason: if available {
            "Microsandbox configured; runtime integrity and effective policy checked at verification"
        } else {
            "requires Microsandbox 0.7.11 and vulnbell sandbox prepare; no host fallback"
        }.into(),
    }
}
fn runtime_command(executable: &Path) -> Result<Command> {
    let home = runtime_home();
    fs::create_dir_all(home.join("home"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("MSB_HOME", home.canonicalize()?)
        .env("HOME", home.join("home").canonicalize()?)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    for key in [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    Ok(command)
}
fn run_runtime(
    executable: &Path,
    args: &[&str],
    seconds: u64,
) -> Result<crate::process::ProcessResult> {
    let mut command = runtime_command(executable)?;
    command.args(args);
    crate::process::run_sandbox_runtime(&mut command, seconds, 1024 * 1024)
}
pub(super) fn checked_runtime(executable: &Path, args: &[&str], seconds: u64) -> Result<Vec<u8>> {
    let result = run_runtime(executable, args, seconds)?;
    if !result.success {
        let diagnostic = runtime_home().join("last-error.stderr");
        crate::atomic_write(&diagnostic, &result.stderr)?;
        bail!(
            "Microsandbox {} failed (exit {:?}); private diagnostic: {}",
            args.first().copied().unwrap_or("operation"),
            result.exit_code,
            diagnostic.display()
        );
    }
    Ok(result.stdout)
}
#[derive(Deserialize)]
struct ImageInspection {
    digest: String,
}
pub(super) fn validate_image(reference: &str) -> Result<()> {
    let (name, digest) = reference
        .split_once("@sha256:")
        .context("image must be pinned by OCI sha256 digest")?;
    if !name.starts_with("docker.io/library/")
        || name.contains("..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("use a digest-pinned official docker.io/library image");
    }
    Ok(())
}
pub fn prepare() -> Result<Image> {
    prepare_image(None)
}
pub fn prepare_image(reference: Option<&str>) -> Result<Image> {
    let executable = match std::env::var_os("VULNBELL_MSB_EXECUTABLE") {
        Some(path) => PathBuf::from(path).canonicalize()?,
        None => {
            let name = if cfg!(windows) { "msb.exe" } else { "msb" };
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|path| path.join(name))
                .find(|path| path.is_file())
                .with_context(|| {
                    format!(
                        "msb was not found on PATH; install Microsandbox {RUNTIME_VERSION} from {RUNTIME_RELEASE} or set VULNBELL_MSB_EXECUTABLE"
                    )
                })?
                .canonicalize()?
        }
    };
    let version = checked_runtime(&executable, &["--version"], 5)?;
    let version = String::from_utf8(version)?.trim().to_owned();
    if version.split_whitespace().last() != Some(RUNTIME_VERSION) {
        bail!(
            "unsupported Microsandbox version `{version}`: install {RUNTIME_VERSION} from {RUNTIME_RELEASE} (msb self downgrade) and rerun backend acceptance before upgrading"
        );
    }
    let doctor = run_runtime(&executable, &["doctor"], 15)?;
    if !doctor.success {
        // Host checks (KVM access, CPU virtualization, libkrunfw) are not secrets; surface the failing lines.
        let output = String::from_utf8_lossy(&doctor.stdout).into_owned()
            + &String::from_utf8_lossy(&doctor.stderr);
        let failing: Vec<&str> = output
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('✗') || line.to_ascii_lowercase().starts_with("error"))
            .take(10)
            .collect();
        bail!(
            "Microsandbox host checks failed: {}; fix the host prerequisites (for KVM: grant /dev/kvm read/write to this user) and rerun vulnbell sandbox prepare",
            if failing.is_empty() {
                "see `msb doctor`".to_owned()
            } else {
                failing.join("; ")
            }
        );
    }
    let image_reference = reference.unwrap_or(DEFAULT_IMAGE);
    validate_image(image_reference)?;
    checked_runtime(
        &executable,
        &["image", "pull", image_reference, "--materialize", "flat"],
        600,
    )?;
    let inspected = checked_runtime(
        &executable,
        &["image", "inspect", image_reference, "--format", "json"],
        15,
    )?;
    let inspected: ImageInspection = serde_json::from_slice(&inspected)?;
    let image = Image {
        schema_version: 2,
        runtime_sha256: crate::digest(&crate::read_limited(&executable, 128 * 1024 * 1024)?),
        runtime_executable: executable,
        runtime_version: version,
        image_reference: image_reference.into(),
        image_manifest_digest: inspected.digest,
    };
    crate::atomic_write(&image_path(), &serde_json::to_vec_pretty(&image)?)?;
    Ok(image)
}
#[derive(Deserialize)]
struct SandboxInspection {
    active_config: Option<RuntimeConfig>,
    #[serde(rename = "config")]
    _desired_config: RuntimeConfig,
}
#[derive(Deserialize)]
struct RuntimeConfig {
    manifest_digest: String,
    deployment_profile: String,
    security_profile: String,
    network: NetworkConfig,
    mounts: Vec<MountConfig>,
    resources: Resources,
    runtime: RuntimeUser,
    external_mount_policy: String,
    image: RuntimeImage,
    lifecycle: RuntimeLifecycle,
}
#[derive(Deserialize)]
struct NetworkConfig {
    policy: NetworkPolicy,
    ports: Vec<serde_json::Value>,
    trust_host_cas: bool,
    secrets: RuntimeSecrets,
}
#[derive(Deserialize)]
struct NetworkPolicy {
    default_egress: String,
    default_ingress: String,
    rules: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
struct RuntimeSecrets {
    secrets: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
struct MountConfig {
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
struct Resources {
    cpus: u32,
    max_cpus: u32,
    memory_mib: u32,
    max_memory_mib: u32,
}
#[derive(Deserialize)]
struct RuntimeUser {
    user: String,
}
#[derive(Deserialize)]
struct RuntimeImage {
    #[serde(rename = "Oci")]
    oci: OciRoot,
}
#[derive(Deserialize)]
struct OciRoot {
    root_disk: RootDisk,
}
#[derive(Deserialize)]
struct RootDisk {
    kind: String,
    size_mib: u32,
}
#[derive(Deserialize)]
struct RuntimeLifecycle {
    max_duration_secs: u64,
}
fn policy_matches(bytes: &[u8], image: &Image, test: &TestSpec) -> Result<bool> {
    let inspected: SandboxInspection = serde_json::from_slice(bytes)?;
    let config = inspected
        .active_config
        .context("runtime did not expose an active policy")?;
    Ok(config.manifest_digest == image.image_manifest_digest
        && config.deployment_profile == "multi_tenant"
        && config.security_profile == "restricted"
        && config.network.policy.default_egress == "deny"
        && config.network.policy.default_ingress == "deny"
        && config.network.policy.rules.is_empty()
        && config.network.ports.is_empty()
        && config.network.secrets.secrets.is_empty()
        && !config.network.trust_host_cas
        && config.mounts.iter().all(|mount| mount.kind == "Tmpfs")
        && config.resources.cpus == 1
        && config.resources.max_cpus == 1
        && config.resources.memory_mib == test.memory_mib
        && config.resources.max_memory_mib == test.memory_mib
        && config.runtime.user == "65534:65534"
        && config.external_mount_policy == "strict"
        && config.image.oci.root_disk.kind == "flat"
        && config.image.oci.root_disk.size_mib == 2048
        && config.lifecycle.max_duration_secs == test.timeout_seconds + 30)
}
struct GuestGuard<'a> {
    executable: &'a Path,
    name: String,
    removed: bool,
}
impl GuestGuard<'_> {
    fn remove(&mut self) -> Result<()> {
        checked_runtime(
            self.executable,
            &["remove", "--force", "--quiet", &self.name],
            15,
        )?;
        self.removed = true;
        Ok(())
    }
}
impl Drop for GuestGuard<'_> {
    fn drop(&mut self) {
        if !self.removed {
            let _ = run_runtime(
                self.executable,
                &["remove", "--force", "--quiet", &self.name],
                15,
            );
        }
    }
}
pub(super) fn execute_guest(
    store: &Store,
    image: &Image,
    test: &TestSpec,
    input_root: &Path,
    limits: &SandboxLimits,
) -> Result<GuestObservation> {
    let temporary = tempfile::tempdir_in(&store.directory)?;
    let script = temporary.path().join("test.sh");
    crate::atomic_write(&script, test.script.as_bytes())?;
    let mut copies = vec![(script, "/radar/test.sh".to_owned())];
    let mut staged_bytes = 0;
    let mut names = std::collections::HashSet::new();
    for input in &test.inputs {
        if input.name.is_empty()
            || input.name.len() > 120
            || input.name.contains(['/', '\\', ':'])
            || input.name == "."
            || input.name == ".."
            || !names.insert(&input.name)
        {
            bail!("input names must be unique plain filenames");
        }
        // A test cannot turn an arbitrary host path into a guest input. Only its inputs/ directory is shared by copy.
        let root = input_root
            .canonicalize()
            .context("create inputs/ beside the test specification")?;
        if root != input_root {
            bail!("inputs/ must not redirect to another directory");
        }
        let source = if input.path.is_absolute() {
            input.path.clone()
        } else {
            input_root
                .parent()
                .context("input directory missing")?
                .join(&input.path)
        };
        let canonical = source.canonicalize()?;
        if !canonical.starts_with(&root) {
            bail!("input path must stay inside inputs/ beside the test specification");
        }
        let bytes = crate::read_limited(&source, u64::from(limits.max_input_file_mib) << 20)?;
        staged_bytes += bytes.len();
        if staged_bytes > (limits.max_inputs_mib as usize) << 20 {
            bail!(
                "inputs exceed {} MiB in total (profile sandbox limits)",
                limits.max_inputs_mib
            );
        }
        if crate::digest(&bytes) != input.sha256 {
            bail!("input checksum mismatch");
        }
        let staged = temporary.path().join(format!("input-{}", copies.len()));
        crate::atomic_write(&staged, &bytes)?;
        copies.push((staged, format!("/radar/inputs/{}", input.name)));
    }
    // Copied files are readable by the unprivileged workload; the private staging directory stays 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (path, _) in &copies {
            fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
        }
    }
    let staging_sha256 = crate::digest(&serde_json::to_vec(test)?);
    let name = format!("vulnbell-{}", uuid::Uuid::new_v4().simple());
    let mut guest = GuestGuard {
        executable: &image.runtime_executable,
        name,
        removed: false,
    };
    let mut command = runtime_command(&image.runtime_executable)?;
    command.args([
        "create",
        "--quiet",
        "--name",
        &guest.name,
        "--no-net",
        "--deployment-profile",
        "multi-tenant",
        "--security",
        "restricted",
        "--user",
        "65534:65534",
        "--cpus",
        "1",
        "--memory",
        &format!("{}M", test.memory_mib),
        "--root-disk",
        "flat:2G",
        "--max-duration",
        &format!("{}s", test.timeout_seconds + 30),
        "--pull",
        "never",
        "--mkdir",
        "/radar",
        "--mkdir",
        "/radar/inputs",
    ]);
    for (source, destination) in &copies {
        command
            .arg("--copy-file")
            .arg(format!("{}:{destination}", source.display()));
    }
    command.arg(&image.image_reference);
    // Creation copies every input into the guest: one extra second per 16 MiB.
    let create_seconds = 30 + (staged_bytes as u64 >> 24);
    let created = crate::process::run_sandbox_runtime(&mut command, create_seconds, 1024 * 1024)?;
    if !created.success {
        let evidence = store.record_evidence(
            &created.stderr,
            "microsandbox_creation_error",
            None,
            EvidenceKind::Context,
        )?;
        bail!(
            "Microsandbox guest creation failed; no workload executed (exit {:?}, private evidence {})",
            created.exit_code,
            evidence.sha256
        );
    }
    let policy = checked_runtime(
        &image.runtime_executable,
        &["inspect", &guest.name, "--format", "json"],
        10,
    )?;
    let policy_evidence = store.record_evidence(
        &policy,
        "microsandbox_effective_policy",
        None,
        EvidenceKind::Context,
    )?;
    if !policy_matches(&policy, image, test)? {
        bail!(
            "Microsandbox active policy differs from the isolation contract; no workload executed; private evidence {}",
            policy_evidence.sha256
        );
    }
    let started = checked_runtime(
        &image.runtime_executable,
        &[
            "exec",
            "--detach",
            "--quiet",
            "--user",
            "65534:65534",
            "--timeout",
            &format!("{}s", test.timeout_seconds),
            &guest.name,
            "--",
            "/bin/sh",
            "/radar/test.sh",
        ],
        10,
    )?;
    let job = String::from_utf8(started)?.trim().to_owned();
    if job.len() != 36
        || !job.starts_with("job_")
        || !job[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("Microsandbox returned an invalid job identity");
    }
    let waited = run_runtime(
        &image.runtime_executable,
        &[
            "wait",
            "--job",
            &job,
            "--timeout",
            &format!("{}s", test.timeout_seconds + 3),
            &guest.name,
        ],
        test.timeout_seconds + 5,
    )?;
    // Control status is fetched separately from workload stdout/stderr through the runtime job protocol.
    let status = checked_runtime(
        &image.runtime_executable,
        &["inspect", &guest.name, "--job", &job, "--format", "json"],
        10,
    )?;
    let inspected: JobInspection = serde_json::from_slice(&status)?;
    let completed = inspected.id == job
        && inspected.state == "exited"
        && inspected.failure.is_none()
        && inspected.error.is_none()
        && inspected
            .exit_code
            .is_some_and(|code| (0..=255).contains(&code));
    let stdout = job_output(&image.runtime_executable, &guest.name, &job, "stdout")?;
    let stderr = job_output(&image.runtime_executable, &guest.name, &job, "stderr")?;
    let process = crate::process::ProcessResult {
        success: completed && inspected.exit_code == Some(0),
        exit_code: inspected.exit_code,
        stdout,
        stderr,
        timed_out: waited.timed_out || inspected.timed_out,
    };
    let oracle_matches = completed
        && process.exit_code == Some(test.oracle.expected_exit)
        && String::from_utf8_lossy(&process.stdout).contains(&test.oracle.stdout_contains);
    let status_evidence = store.record_evidence(
        &status,
        "microsandbox_job_status",
        None,
        EvidenceKind::Context,
    )?;
    if let Err(error) = guest.remove() {
        let evidence = store.record_evidence(
            error.to_string().as_bytes(),
            "microsandbox_cleanup_error",
            None,
            EvidenceKind::Context,
        )?;
        bail!(
            "guest cleanup failed; verification remains inconclusive; private evidence {}",
            evidence.sha256
        );
    }
    let policy_ok = true;
    Ok(GuestObservation {
        process,
        staging_sha256,
        policy_sha256: policy_evidence.sha256.clone(),
        policy_ok,
        completed,
        policy_evidence,
        status_evidence,
        oracle_matches,
    })
}
#[derive(Deserialize)]
struct JobInspection {
    id: String,
    state: String,
    exit_code: Option<i32>,
    failure: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
    timed_out: bool,
}

fn job_output(executable: &Path, name: &str, job: &str, source: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let bytes = checked_runtime(
        executable,
        &["logs", "--job", job, "--source", source, "--json", name],
        10,
    )?;
    #[derive(Deserialize)]
    struct LogEntry {
        id: String,
        s: String,
        d: String,
        e: Option<String>,
    }
    let mut output = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let entry: LogEntry = serde_json::from_slice(line)?;
        if entry.id != job || entry.s != source {
            bail!("runtime log identity mismatch");
        }
        let data = match entry.e.as_deref() {
            None => entry.d.into_bytes(),
            Some("base64") => base64::engine::general_purpose::STANDARD.decode(entry.d)?,
            Some(_) => bail!("unsupported runtime log encoding"),
        };
        if output.len() + data.len() > 1024 * 1024 {
            bail!("guest output limit exceeded; no verification result accepted");
        }
        output.extend(data);
    }
    Ok(output)
}
