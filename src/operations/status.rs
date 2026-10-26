use super::systemd_command;
use crate::{profile::Schedule, store::Store};
use anyhow::{Context, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Serialize, JsonSchema)]
pub struct StatusReport {
    pub schema_version: u32,
    pub data_directory: PathBuf,
    pub projects_found: usize,
    pub projects: Vec<ProjectStatus>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ProjectStatus {
    pub project_id: String,
    pub name: Option<String>,
    pub profile: Option<PathBuf>,
    pub profile_available: bool,
    pub scan: ScanStatus,
    pub schedule: ProjectScheduleStatus,
    pub last_report: Option<PathBuf>,
    pub last_agent_review: Option<String>,
    pub last_agent_success: Option<String>,
    pub last_agent_failure: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ScanStatus {
    pub last_started_at: Option<String>,
    pub last_completed_at: Option<String>,
    pub last_successful_at: Option<String>,
    pub outcome: Option<String>,
    pub last_failure: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ProjectScheduleStatus {
    pub requested: Option<Schedule>,
    pub configured: bool,
    pub configuration_valid: bool,
    pub runner: Option<String>,
    pub runner_configured: bool,
    pub installed: bool,
    pub timer_active: Option<bool>,
    pub timer_state: Option<String>,
    pub next_run: Option<String>,
    pub last_trigger: Option<String>,
    pub last_job_at: Option<String>,
    pub last_job_outcome: Option<String>,
    pub last_skipped_job: Option<SkippedJob>,
    pub scheduler_failure: Option<String>,
    pub healthy: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkippedJob {
    pub schema_version: u32,
    pub state: String,
    pub slot: String,
    pub expires_at: String,
    pub next_iteration: String,
}

struct TimerInspection {
    installed: bool,
    active: Option<bool>,
    state: Option<String>,
    next_run: Option<String>,
    last_trigger: Option<String>,
    error: Option<String>,
}

pub fn status() -> Result<StatusReport> {
    let data_directory = crate::store::data_root();
    if !data_directory.exists() {
        return Ok(StatusReport {
            schema_version: 1,
            data_directory,
            projects_found: 0,
            projects: Vec::new(),
        });
    }
    if data_directory.is_symlink() || !data_directory.is_dir() {
        bail!("VulnBell data directory must be a real directory");
    }
    let mut projects = Vec::new();
    for entry in fs::read_dir(&data_directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let project_id = entry.file_name().to_string_lossy().into_owned();
        if project_id.parse::<uuid::Uuid>().is_err() {
            continue;
        }
        let project = match Store::open_existing(&project_id) {
            Ok(store) => project_status(&store)?,
            Err(error) => unavailable_project(project_id, error.to_string()),
        };
        projects.push(project);
    }
    projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));
    Ok(StatusReport {
        schema_version: 1,
        data_directory,
        projects_found: projects.len(),
        projects,
    })
}

pub fn status_markdown(report: &StatusReport) -> String {
    let mut text = format!("# VulnBell status\n\nProjects: {}\n", report.projects_found);
    if report.projects.is_empty() {
        text.push_str("\nNo monitored projects are registered.\n");
        return text;
    }
    for project in &report.projects {
        text.push_str(&format!(
            "\n## {}\n\n",
            one_line(project.name.as_deref().unwrap_or(&project.project_id))
        ));
        text.push_str(&format!("- Project ID: `{}`\n", project.project_id));
        let profile = project
            .profile
            .as_ref()
            .map(|path| one_line(&path.display().to_string()))
            .unwrap_or_else(|| "not recorded".to_owned());
        text.push_str(&format!("- Profile: {profile}\n"));
        let scan = match (&project.scan.outcome, &project.scan.last_completed_at) {
            (Some(outcome), Some(completed)) => {
                format!("{} at {}", one_line(outcome), one_line(completed))
            }
            _ => "never completed".to_owned(),
        };
        text.push_str(&format!("- Scan: {scan}\n"));
        let schedule = if project.schedule.healthy {
            "active"
        } else if project.schedule.requested.is_some() {
            "requested but not ready"
        } else {
            "not requested"
        };
        text.push_str(&format!("- Schedule: {schedule}\n"));
        if let Some(runner) = &project.schedule.runner {
            let state = if project.schedule.runner_configured {
                "configured"
            } else {
                "missing"
            };
            text.push_str(&format!("- Runner: `{}` ({state})\n", one_line(runner)));
        }
        if let Some(outcome) = &project.schedule.last_job_outcome {
            text.push_str(&format!("- Last job: {}\n", one_line(outcome)));
        }
        if let Some(skipped) = &project.schedule.last_skipped_job {
            text.push_str(&format!(
                "- Last skipped slot: {} (expired {})\n",
                one_line(&skipped.slot),
                one_line(&skipped.expires_at)
            ));
        }
        if let Some(report) = &project.last_report {
            text.push_str(&format!(
                "- Last report: {}\n",
                one_line(&report.display().to_string())
            ));
        }
        for error in &project.errors {
            text.push_str(&format!("- Problem: {}\n", one_line(error)));
        }
    }
    text
}

pub(super) fn project_status(store: &Store) -> Result<ProjectStatus> {
    let project_id = store
        .directory
        .file_name()
        .context("project state directory has no project ID")?
        .to_string_lossy()
        .into_owned();
    let mut errors = Vec::new();
    let profile_path = store.meta("profile_path")?.map(PathBuf::from);
    let profile = match profile_path.as_deref() {
        Some(path) => match crate::profile::load(path) {
            Ok(profile) => Some(profile),
            Err(error) => {
                errors.push(format!("profile unavailable or invalid: {error}"));
                None
            }
        },
        None => {
            errors.push("profile path is not recorded".to_owned());
            None
        }
    };
    let schedule_configured = crate::scheduler::config_path(store).is_file();
    let schedule = if schedule_configured {
        match profile.as_ref() {
            Some(profile) => match crate::scheduler::load_config(profile, store) {
                Ok(config) => Some(config),
                Err(error) => {
                    errors.push(format!("schedule configuration is invalid: {error}"));
                    None
                }
            },
            None => None,
        }
    } else {
        None
    };
    let configuration_valid = schedule.is_some();
    let runner = schedule.as_ref().map(|config| config.runner.clone());
    let runner_configured = match runner.as_deref() {
        Some(id) => match crate::runners::load(id) {
            Ok(_) => true,
            Err(error) => {
                errors.push(format!("runner '{id}' is unavailable or invalid: {error}"));
                false
            }
        },
        None => false,
    };
    let timer_id = store.meta("scheduler_id")?;
    let timer = inspect_timer(timer_id.as_deref());
    if let Some(error) = &timer.error {
        errors.push(error.clone());
    }
    let last_skipped_job = match store.meta("last_skipped_job")? {
        Some(value) => match serde_json::from_str(&value) {
            Ok(skipped) => Some(skipped),
            Err(error) => {
                errors.push(format!("last skipped job state is invalid: {error}"));
                None
            }
        },
        None => None,
    };
    let requested = profile
        .as_ref()
        .and_then(|profile| profile.schedule.clone());
    let healthy = requested.is_some()
        && configuration_valid
        && runner_configured
        && timer.installed
        && timer.active == Some(true);
    Ok(ProjectStatus {
        project_id,
        name: store.meta("project_name")?,
        profile: profile_path,
        profile_available: profile.is_some(),
        scan: ScanStatus {
            last_started_at: store.meta("last_scan")?,
            last_completed_at: store.meta("last_completed_scan")?,
            last_successful_at: store.meta("last_successful_scan")?,
            outcome: store.meta("last_scan_outcome")?,
            last_failure: store.meta("last_failure")?,
        },
        schedule: ProjectScheduleStatus {
            requested,
            configured: schedule_configured,
            configuration_valid,
            runner,
            runner_configured,
            installed: timer.installed,
            timer_active: timer.active,
            timer_state: timer.state,
            next_run: timer.next_run,
            last_trigger: timer.last_trigger,
            last_job_at: store.meta("last_job")?,
            last_job_outcome: store.meta("last_job_outcome")?,
            last_skipped_job,
            scheduler_failure: store.meta("scheduler_failure")?,
            healthy,
        },
        last_report: store.meta("last_report")?.map(PathBuf::from),
        last_agent_review: store.meta("last_agent_review")?,
        last_agent_success: store.meta("last_agent_success")?,
        last_agent_failure: store.meta("last_agent_failure")?,
        errors,
    })
}

fn unavailable_project(project_id: String, error: String) -> ProjectStatus {
    ProjectStatus {
        project_id,
        name: None,
        profile: None,
        profile_available: false,
        scan: ScanStatus {
            last_started_at: None,
            last_completed_at: None,
            last_successful_at: None,
            outcome: None,
            last_failure: None,
        },
        schedule: ProjectScheduleStatus {
            requested: None,
            configured: false,
            configuration_valid: false,
            runner: None,
            runner_configured: false,
            installed: false,
            timer_active: None,
            timer_state: None,
            next_run: None,
            last_trigger: None,
            last_job_at: None,
            last_job_outcome: None,
            last_skipped_job: None,
            scheduler_failure: None,
            healthy: false,
        },
        last_report: None,
        last_agent_review: None,
        last_agent_success: None,
        last_agent_failure: None,
        errors: vec![format!("cannot read project state: {error}")],
    }
}

fn inspect_timer(timer: Option<&str>) -> TimerInspection {
    let Some(timer) = timer else {
        return TimerInspection {
            installed: false,
            active: None,
            state: None,
            next_run: None,
            last_trigger: None,
            error: None,
        };
    };
    let result = match systemd_command(&[
        "show",
        timer,
        "--property=LoadState,ActiveState,NextElapseUSecRealtime,LastTriggerUSec",
    ]) {
        Ok(result) => result,
        Err(error) => {
            return TimerInspection {
                installed: false,
                active: None,
                state: None,
                next_run: None,
                last_trigger: None,
                error: Some(format!("cannot inspect scheduler timer: {error}")),
            };
        }
    };
    if !result.success {
        return TimerInspection {
            installed: false,
            active: None,
            state: None,
            next_run: None,
            last_trigger: None,
            error: Some("scheduler timer is not available".to_owned()),
        };
    }
    let output = String::from_utf8_lossy(&result.stdout);
    let property = |name: &str| {
        output.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
    };
    let load_state = property("LoadState");
    let active_state = property("ActiveState");
    TimerInspection {
        installed: load_state.as_deref() == Some("loaded"),
        active: active_state.as_deref().map(|state| state == "active"),
        state: active_state,
        next_run: property("NextElapseUSecRealtime"),
        last_trigger: property("LastTriggerUSec"),
        error: None,
    }
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .take(500)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}
