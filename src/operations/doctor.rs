use anyhow::Result;
use serde::Serialize;
use std::{
    fmt::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Serialize)]
pub struct DoctorReport {
    schema_version: u8,
    cli_version: &'static str,
    data_directory: PathBuf,
    data_directory_access: &'static str,
    skills: Vec<crate::skills::SkillStatus>,
    credentials: Credentials,
    tools: Vec<Tool>,
    pdf_browser: Option<PathBuf>,
    sandbox: crate::model::SandboxAvailability,
    scheduler: Scheduler,
    runners: Runners,
    connectivity: &'static str,
}

#[derive(Serialize)]
struct Credentials {
    github: bool,
    github_source: Option<&'static str>,
    nvd: bool,
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    purpose: &'static str,
    executable: Option<PathBuf>,
}

#[derive(Serialize)]
struct Scheduler {
    systemd_user: bool,
}

#[derive(Serialize)]
struct Runners {
    configured: Vec<crate::runners::RunnerSummary>,
    adapters: Vec<crate::runners::AdapterInfo>,
    missing_executables: Vec<String>,
    configuration_error: Option<&'static str>,
}

pub fn doctor() -> Result<DoctorReport> {
    let skill_status = crate::skills::status()?;
    let (runners, configuration_error) = match crate::runners::list() {
        Ok(runners) => (runners, None),
        Err(_) => (
            Vec::new(),
            Some("Runner configuration cannot be read; run vulnbell runners list --json."),
        ),
    };
    let missing_executables = runners
        .iter()
        .filter(|runner| !executable(&runner.executable))
        .map(|runner| runner.id.clone())
        .collect();
    let mut command = Command::new("systemctl");
    command.env_clear().env("PATH", "/usr/bin:/bin");
    for key in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.args(["--user", "show-environment"]);
    let scheduler =
        crate::process::run_bounded(&mut command, 5, 65536).is_ok_and(|result| result.success);
    let github = crate::network::github_credentials();
    let tools = [
        (
            "git",
            "Git codebase revisions and public source trees",
            &["git", "git.exe"][..],
        ),
        ("gh", "GitHub tracker research", &["gh", "gh.exe"][..]),
        (
            "curl",
            "public upstream research",
            &["curl", "curl.exe"][..],
        ),
        ("jq", "upstream research workflow", &["jq", "jq.exe"][..]),
        (
            "python",
            "optional structured-data helper",
            &["python3", "python.exe", "python"][..],
        ),
        (
            "cargo-audit",
            "optional Rust lockfile audit",
            &["cargo-audit", "cargo-audit.exe"][..],
        ),
    ]
    .into_iter()
    .map(|(name, purpose, names)| Tool {
        name,
        purpose,
        executable: find_tool(names),
    })
    .collect();
    let data_directory = crate::store::data_root();
    let data_directory_access = data_directory_access(&data_directory);
    Ok(DoctorReport {
        schema_version: 1,
        cli_version: env!("CARGO_PKG_VERSION"),
        data_directory,
        data_directory_access,
        skills: skill_status,
        credentials: Credentials {
            github: github.is_some(),
            github_source: github.as_ref().map(|value| value.source),
            nvd: std::env::var_os("NVD_API_KEY").is_some_and(|value| !value.is_empty()),
        },
        tools,
        pdf_browser: crate::output::browser_path(None).ok(),
        sandbox: crate::sandbox::availability(),
        scheduler: Scheduler {
            systemd_user: scheduler,
        },
        runners: Runners {
            configured: runners,
            adapters: crate::runners::adapter_catalog(),
            missing_executables,
            configuration_error,
        },
        connectivity: "not_checked: scan reports per-source network evidence",
    })
}

fn data_directory_access(path: &Path) -> &'static str {
    match std::fs::metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && tempfile::Builder::new()
                    .prefix(".vulnbell-doctor-")
                    .tempfile_in(path)
                    .is_ok() =>
        {
            "writable"
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && path
                    .ancestors()
                    .skip(1)
                    .find(|parent| parent.try_exists().unwrap_or(true))
                    .is_some_and(|parent| {
                        parent.is_dir()
                            && tempfile::Builder::new()
                                .prefix(".vulnbell-doctor-")
                                .tempfile_in(parent)
                                .is_ok()
                    }) =>
        {
            "parent_writable"
        }
        _ => "unwritable",
    }
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_tool(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        for name in names {
            let candidate = directory.join(name);
            if executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn line(out: &mut String, good: bool, text: &str, color: bool) {
    let (label, code) = if good { ("OK", "32") } else { ("CHECK", "33") };
    if color {
        let _ = writeln!(out, "  \x1b[{code}m{label:5}\x1b[0m {text}");
    } else {
        let _ = writeln!(out, "  {label:5} {text}");
    }
}

fn info(out: &mut String, text: &str, color: bool) {
    if color {
        let _ = writeln!(out, "  \x1b[36mINFO \x1b[0m {text}");
    } else {
        let _ = writeln!(out, "  INFO  {text}");
    }
}

pub fn doctor_text(report: &DoctorReport, color: bool) -> String {
    let mut out = format!("VulnBell {} — environment check\n\n", report.cli_version);
    out.push_str("Interactive review\n");
    let data = match report.data_directory_access {
        "writable" => format!(
            "Data directory is writable: {}",
            report.data_directory.display()
        ),
        "parent_writable" => format!(
            "Data directory does not exist yet; an existing parent is writable: {}",
            report.data_directory.display()
        ),
        _ => format!(
            "Data directory is not writable or cannot be created: {}",
            report.data_directory.display()
        ),
    };
    line(
        &mut out,
        report.data_directory_access != "unwritable",
        &data,
        color,
    );
    for skill in &report.skills {
        let message = if skill.version_aligned_and_unmodified {
            format!("Skill installed and current: {}", skill.directory.display())
        } else {
            format!(
                "Skill missing or different: {}. Reinstall it at this path; preserve local edits first.",
                skill.directory.display()
            )
        };
        line(
            &mut out,
            skill.version_aligned_and_unmodified,
            &message,
            color,
        );
    }
    if report.credentials.github {
        line(
            &mut out,
            true,
            &format!(
                "GitHub credential available via {}; permissions not checked",
                report.credentials.github_source.unwrap_or("unknown")
            ),
            color,
        );
    } else {
        line(
            &mut out,
            false,
            "GitHub credential unavailable; run gh auth login for gh-based tracker research; anonymous advisory requests have lower limits",
            color,
        );
    }
    for tool in &report.tools {
        let message = match &tool.executable {
            Some(path) => format!("{}: {} ({})", tool.name, path.display(), tool.purpose),
            None => format!("{} not found; needed for {}", tool.name, tool.purpose),
        };
        line(&mut out, tool.executable.is_some(), &message, color);
    }
    out.push_str("\nOptional capabilities\n");
    let pdf = report
        .pdf_browser
        .as_ref()
        .map(|path| format!("PDF browser found: {} (not tested)", path.display()))
        .unwrap_or_else(|| {
            "PDF browser not found; install Chromium or pass --pdf-browser for PDF export".into()
        });
    line(&mut out, report.pdf_browser.is_some(), &pdf, color);
    let sandbox = if report.sandbox.available {
        "Sandbox configured; runtime and isolation are checked during verification"
    } else {
        "Sandbox not prepared; run vulnbell sandbox prepare only if a test is needed"
    };
    line(&mut out, report.sandbox.available, sandbox, color);
    line(
        &mut out,
        report.credentials.nvd,
        if report.credentials.nvd {
            "NVD API key configured; validity not checked"
        } else {
            "NVD API key not configured; optional, anonymous requests have lower limits"
        },
        color,
    );
    line(
        &mut out,
        report.scheduler.systemd_user,
        if report.scheduler.systemd_user {
            "systemd user scheduler available"
        } else {
            "systemd user scheduler unavailable; needed only for Linux scheduling"
        },
        color,
    );
    if let Some(error) = report.runners.configuration_error {
        line(&mut out, false, error, color);
    } else if report.runners.configured.is_empty() {
        line(
            &mut out,
            false,
            "No local runner configured; needed only for scheduled or on-demand agent runs",
            color,
        );
    } else {
        for runner in &report.runners.configured {
            let available = !report.runners.missing_executables.contains(&runner.id);
            let message = if available {
                format!(
                    "Runner {} executable found; compatibility not checked. Run vulnbell runners check {}",
                    runner.id, runner.id
                )
            } else {
                format!(
                    "Runner {} executable is missing or not executable: {}",
                    runner.id,
                    runner.executable.display()
                )
            };
            if available {
                info(&mut out, &message, color);
            } else {
                line(&mut out, false, &message, color);
            }
        }
    }
    out.push_str("\nNetwork access and credential permissions are not checked. Scans report source coverage.\nOptional checks are only needed for the workflows listed above.\n");
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn status_colors_are_opt_in() {
        let mut plain = String::new();
        super::line(&mut plain, true, "available", false);
        super::line(&mut plain, false, "missing", false);
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("OK   "));
        assert!(plain.contains("CHECK"));
        let mut colored = String::new();
        super::line(&mut colored, true, "available", true);
        super::line(&mut colored, false, "missing", true);
        assert!(colored.contains("\x1b[32m"));
        assert!(colored.contains("\x1b[33m"));
    }

    #[test]
    fn data_directory_probe_reports_missing_and_invalid_paths() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(super::data_directory_access(root.path()), "writable");
        assert_eq!(
            super::data_directory_access(&root.path().join("future")),
            "parent_writable"
        );
        let file = root.path().join("file");
        std::fs::write(&file, "not a directory").unwrap();
        assert_eq!(super::data_directory_access(&file), "unwritable");
        assert_eq!(
            super::data_directory_access(&file.join("child")),
            "unwritable"
        );
    }
}
