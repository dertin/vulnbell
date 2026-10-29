use crate::{
    process::{ProcessResult, run_bounded},
    profile::Profile,
    store::Store,
};
use anyhow::{Context, Result, bail};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

mod status;
pub use status::{StatusReport, status, status_markdown};

pub fn doctor() -> Result<serde_json::Value> {
    let skill_status = crate::skills::status()?;
    let runners = crate::runners::list()?;
    let mut command = Command::new("systemctl");
    command.env_clear().env("PATH", "/usr/bin:/bin");
    for key in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.args(["--user", "show-environment"]);
    let scheduler = run_bounded(&mut command, 5, 65536).is_ok_and(|result| result.success);
    Ok(
        serde_json::json!({"schema_version":1,"cli_version":env!("CARGO_PKG_VERSION"),"data_directory":crate::store::data_root(),"skills":skill_status,"sandbox":crate::sandbox::availability(),"scheduler":{"systemd_user":scheduler,"unattended_agent_review":false},"runners":{"configured":runners,"adapters":crate::runners::adapter_catalog()},"credentials":{"github":std::env::var_os("GITHUB_TOKEN").is_some(),"nvd":std::env::var_os("NVD_API_KEY").is_some()},"connectivity":"not_checked: scan reports per-source network evidence"}),
    )
}
fn systemd_command(args: &[&str]) -> Result<ProcessResult> {
    let mut command = Command::new("systemctl");
    command.env_clear().env("PATH", "/usr/bin:/bin");
    for key in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.arg("--user").args(args);
    run_bounded(&mut command, 120, 65536)
}
fn unit_quote(path: &Path) -> Result<String> {
    let value = path.to_str().context("systemd paths must be UTF-8")?;
    if value.chars().any(char::is_control) {
        bail!("control character in scheduler path");
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

/// Disables the timer and deletes only units this project manages; history stays in the store.
fn remove_schedule(
    profile: &Profile,
    store: &Store,
    timer: &str,
    service: &str,
) -> Result<serde_json::Value> {
    let directory = crate::user_home()?.join(".config/systemd/user");
    let mut removed = Vec::new();
    for name in [timer, service] {
        let target = directory.join(name);
        if !target.exists() {
            continue;
        }
        let content = String::from_utf8(crate::read_limited(&target, 65536)?)?;
        if !content.contains(&format!("VulnBell {}", profile.project_id)) {
            bail!("scheduler unit {name} is unmanaged; refusing removal");
        }
        if name == timer {
            let result = systemd_command(&["disable", "--now", timer])?;
            if !result.success {
                bail!("cannot disable {timer}; inspect systemctl --user status {timer}");
            }
        }
        std::fs::remove_file(&target)?;
        removed.push(name.to_owned());
    }
    if !removed.is_empty() && !systemd_command(&["daemon-reload"])?.success {
        bail!("units removed but systemctl --user daemon-reload failed");
    }
    store
        .connection
        .execute("DELETE FROM meta WHERE key='scheduler_id'", [])?;
    Ok(serde_json::json!({"schema_version":1,"removed_units":removed}))
}

pub fn schedule(
    profile: &Profile,
    path: &Path,
    action: &str,
    config_path: Option<&Path>,
) -> Result<serde_json::Value> {
    let store = Store::open(&profile.project_id.to_string())?;
    store.register_project(&profile.name, path)?;
    let id = format!("vulnbell-{}", profile.project_id);
    let timer = format!("{id}.timer");
    let service = format!("{id}.service");
    if action == "status" {
        return Ok(serde_json::to_value(status::project_status(&store)?)?);
    }
    if action == "remove" {
        return remove_schedule(profile, &store, &timer, &service);
    }
    if action != "install" {
        bail!("scheduler action must be install, status or remove");
    }
    if profile.schedule.is_none() {
        bail!("profile must request schedule: daily, weekdays or weekly");
    }
    if !systemd_command(&["show-environment"])?.success {
        bail!("systemd user scheduler unavailable; no job installed");
    }
    if let Some(config_path) = config_path {
        let bytes = crate::read_limited(config_path, 65536)?;
        let config = crate::scheduler::parse_config(profile, &bytes)?;
        crate::scheduler::save_config(profile, &store, &config)?;
    }
    let config = crate::scheduler::load_config(profile, &store)?;
    crate::runners::load(&config.runner).with_context(|| {
        format!(
            "schedule references runner '{}'; configure it before installing the job",
            config.runner
        )
    })?;
    let path = path.canonicalize()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let directory = crate::user_home()?.join(".config/systemd/user");
    let data = crate::store::data_root();
    let data = if data.is_absolute() {
        data
    } else {
        std::env::current_dir()?.join(data)
    };
    let mut body = format!(
        "[Unit]\nDescription=VulnBell {}\n[Service]\nType=oneshot\nExecStart={} run --project {}\nTimeoutStartSec=24h\nMemoryMax=3G\nEnvironment={}\nEnvironmentFile={}\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n",
        profile.project_id,
        unit_quote(&executable)?,
        unit_quote(&path)?,
        unit_quote(Path::new(&format!("VULNBELL_DATA_DIR={}", data.display())))?,
        unit_quote(Path::new(&format!(
            "-{}",
            store.directory.join("alerts.env").display()
        )))?
    );
    for variable in ["CODEX_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"] {
        if let Some(value) = std::env::var_os(variable) {
            let environment = format!("{variable}={}", value.to_string_lossy());
            body.push_str(&format!(
                "Environment={}\n",
                unit_quote(Path::new(&environment))?
            ));
        }
    }
    if let Some(path_value) = std::env::var_os("PATH") {
        body.push_str(&format!(
            "Environment={}\n",
            unit_quote(Path::new(&format!("PATH={}", path_value.to_string_lossy())))?
        ));
    }
    if let Some(certificate_file) = std::env::var_os("SSL_CERT_FILE") {
        let environment = format!(
            "SSL_CERT_FILE={}",
            PathBuf::from(certificate_file).display()
        );
        body.push_str(&format!(
            "Environment={}\n",
            unit_quote(Path::new(&environment))?
        ));
    }
    for (name, content) in [
        (&service, body),
        (
            &timer,
            format!(
                "[Unit]\nDescription=Daily VulnBell {}\n[Timer]\nOnCalendar={}\nAccuracySec=1min\nRandomizedDelaySec=0\nPersistent=true\n[Install]\nWantedBy=timers.target\n",
                profile.project_id,
                crate::scheduler::calendar(&config)
            ),
        ),
    ] {
        let target = directory.join(name);
        if target.exists() {
            let old = String::from_utf8(crate::read_limited(&target, 65536)?)?;
            if !old.contains(&format!("VulnBell {}", profile.project_id)) {
                bail!("scheduler unit is unmanaged; refusing overwrite");
            }
        }
        crate::atomic_write(&target, content.as_bytes())?;
    }
    for args in [
        vec!["daemon-reload"],
        vec!["enable", "--now", &timer],
        vec!["start", "--no-block", &service],
    ] {
        let result = systemd_command(&args)?;
        if !result.success {
            store.set_meta("scheduler_failure", &crate::now())?;
            bail!("scheduler command failed; inspect systemctl --user status {service}");
        }
    }
    store.set_meta("scheduler_id", &timer)?;
    Ok(serde_json::to_value(status::project_status(&store)?)?)
}
