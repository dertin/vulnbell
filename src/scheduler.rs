use crate::{
    output::text::{self, fill},
    profile::Profile,
    store::Store,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Duration, NaiveTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    pub schema_version: u32,
    pub project_id: String,
    pub runner: String,
    pub timezone: String,
    pub at: String,
    pub window_minutes: u16,
    pub frequency: Frequency,
    pub report_dir: PathBuf,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    Daily,
    Weekdays,
    Weekly,
}
#[derive(Debug, PartialEq, Eq)]
pub enum SlotState {
    Eligible,
    BeforeFirstSlot,
    Expired,
}
#[derive(Debug)]
pub struct Slot {
    pub id: String,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: SlotState,
}
impl ScheduleConfig {
    pub fn validate(&self, profile: &Profile) -> Result<()> {
        if self.schema_version != 2 || self.project_id != profile.project_id.to_string() {
            bail!("schedule configuration belongs to another project/schema");
        }
        crate::runners::validate_id(&self.runner)?;
        let frequency_matches = matches!(
            (&profile.schedule, self.frequency),
            (Some(crate::profile::Schedule::Daily), Frequency::Daily)
                | (
                    Some(crate::profile::Schedule::Weekdays),
                    Frequency::Weekdays
                )
                | (Some(crate::profile::Schedule::Weekly), Frequency::Weekly)
        );
        if !frequency_matches {
            bail!("schedule frequency must match the profile's daily/weekly/weekdays intent");
        }
        let _: Tz = self
            .timezone
            .parse()
            .map_err(|_| anyhow::anyhow!("unknown IANA timezone"))?;
        NaiveTime::parse_from_str(&self.at, "%H:%M").context("at must be HH:MM")?;
        if self.window_minutes == 0 || self.window_minutes > 1440 {
            bail!("window_minutes must be 1..1440");
        }
        if !self.report_dir.is_absolute() {
            bail!("report_dir must be an absolute path");
        }
        Ok(())
    }
    pub fn slot(&self, now: DateTime<Utc>) -> Result<Slot> {
        let timezone: Tz = self
            .timezone
            .parse()
            .map_err(|_| anyhow::anyhow!("unknown timezone"))?;
        let time = NaiveTime::parse_from_str(&self.at, "%H:%M")?;
        let local = now.with_timezone(&timezone);
        for days_ago in 0..=8 {
            let day = local.date_naive() - Duration::days(days_ago);
            let weekday = day.weekday();
            let included = match self.frequency {
                Frequency::Daily => true,
                Frequency::Weekdays => weekday.number_from_monday() <= 5,
                Frequency::Weekly => weekday == chrono::Weekday::Mon,
            };
            if !included {
                continue;
            }
            let Some(start) = timezone.from_local_datetime(&day.and_time(time)).earliest() else {
                continue;
            };
            let starts_at = start.with_timezone(&Utc);
            if starts_at > now {
                continue;
            }
            let expires_at = starts_at + Duration::minutes(i64::from(self.window_minutes));
            return Ok(Slot {
                id: format!("{}-{:02}{:02}", day, time.hour(), time.minute()),
                starts_at,
                expires_at,
                state: if now < expires_at {
                    SlotState::Eligible
                } else {
                    SlotState::Expired
                },
            });
        }
        Ok(Slot {
            id: "none".into(),
            starts_at: now,
            expires_at: now,
            state: SlotState::BeforeFirstSlot,
        })
    }
}
pub fn config_path(store: &Store) -> PathBuf {
    store.directory.join("schedule.json")
}
pub fn save_config(profile: &Profile, store: &Store, config: &ScheduleConfig) -> Result<()> {
    config.validate(profile)?;
    crate::atomic_write(&config_path(store), &serde_json::to_vec_pretty(config)?)
}
pub fn parse_config(profile: &Profile, bytes: &[u8]) -> Result<ScheduleConfig> {
    let config: ScheduleConfig = serde_json::from_slice(bytes)?;
    config.validate(profile)?;
    Ok(config)
}
pub fn load_config(profile: &Profile, store: &Store) -> Result<ScheduleConfig> {
    let bytes = crate::read_limited(&config_path(store), 65536)?;
    parse_config(profile, &bytes)
}
pub fn calendar(config: &ScheduleConfig) -> String {
    let prefix = match config.frequency {
        Frequency::Daily => "*-*-*",
        Frequency::Weekdays => "Mon..Fri *-*-*",
        Frequency::Weekly => "Mon *-*-*",
    };
    format!("{prefix} {}:00 {}", config.at, config.timezone)
}
pub fn run(profile: &Profile, profile_path: &Path, force: bool) -> Result<serde_json::Value> {
    let store = Store::open(&profile.project_id.to_string())?;
    let config = load_config(profile, &store)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(store.directory.join("job.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("scheduled agent job is already running")?;
    let current = Utc::now();
    let slot = config.slot(current)?;
    if !force && slot.state != SlotState::Eligible {
        let result = serde_json::json!({"schema_version":1,"state":"skipped_expired","slot":slot.id,"expires_at":slot.expires_at,"next_iteration":"timer schedule; no late catch-up"});
        store.set_meta("last_skipped_job", &result.to_string())?;
        return Ok(result);
    }
    let slot_key = if force {
        format!("manual-{}", uuid::Uuid::new_v4())
    } else {
        slot.id.clone()
    };
    let config_hash = crate::digest(&serde_json::to_vec(&config)?);
    let completion = format!("{config_hash}:{slot_key}");
    if !force && store.meta("last_completed_slot")?.as_deref() == Some(&completion) {
        return Ok(
            serde_json::json!({"schema_version":1,"state":"already_completed","slot":slot.id}),
        );
    }
    let run_id = format!(
        "{slot_key}-{}-{}",
        &config_hash[..8],
        uuid::Uuid::new_v4().simple()
    );
    let directory = store.directory.join("jobs").join(&run_id);
    let result = (|| -> Result<serde_json::Value> {
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        // Count the initial scan against an explicitly configured review budget. The scan itself is
        // synchronous, so a slow scan can overrun it; subsequent agent calls will not start afterward.
        let budget_deadline = profile
            .research
            .review_budget_minutes
            .map(|minutes| current + Duration::minutes(i64::from(minutes)));
        crate::engine::scan(profile, profile_path, false)?;
        let mut store = Store::open(&profile.project_id.to_string())?;
        let window_deadline = if force {
            budget_deadline.unwrap_or_else(|| Utc::now() + Duration::seconds(900))
        } else {
            slot.expires_at
        };
        let deadline = budget_deadline.map_or(window_deadline, |end| window_deadline.min(end));
        let discovery_error = crate::discovery::automation::run(
            profile,
            profile_path,
            &mut store,
            &config.runner,
            &directory.join("discovery"),
            deadline,
        )
        .err()
        .map(|error| error.to_string());
        let remaining_seconds = (deadline - Utc::now()).num_seconds().max(0);
        let impact_deadline = Utc::now() + Duration::seconds(remaining_seconds / 2);
        let mut impact_error = crate::impact::automation::run(
            &mut store,
            &config.runner,
            profile_path,
            &directory.join("impact"),
            impact_deadline,
        )
        .err()
        .map(|error| error.to_string());
        let agent_directory = directory.join("agent-work");
        let mut research_error = crate::research::automation::run(
            &mut store,
            &config.runner,
            &directory,
            &agent_directory,
            deadline,
        )
        .err()
        .map(|error| error.to_string());
        if Utc::now() < deadline {
            impact_error = crate::impact::automation::run(
                &mut store,
                &config.runner,
                profile_path,
                &directory.join("impact"),
                deadline,
            )
            .err()
            .map(|error| error.to_string());
        }
        research_error = match (discovery_error, research_error) {
            (Some(discovery), Some(research)) => Some(format!("{discovery}; {research}")),
            (Some(discovery), None) => Some(discovery),
            (None, research) => research,
        };
        let (report_snapshot, report, pending) = {
            let _lock = store.lock()?;
            let mut report_snapshot = store.latest()?;
            report_snapshot.cases = store.cases()?;
            let mut report = crate::output::morning_report(&report_snapshot, &store, "manager")?;
            let pending = crate::tools::cases::pending(&store)?;
            crate::output::add_research_coverage(&mut report, &pending);
            crate::output::prepare_report_paths(&mut report, &store)?;
            (report_snapshot, report, pending)
        };
        let report_data = directory.join("morning-data.json");
        crate::atomic_write(&report_data, &serde_json::to_vec_pretty(&report)?)?;
        let words = text::text(report.language);
        let mut text = format!(
            "{}{}",
            crate::output::delivery_status_markdown(
                &pending,
                report_snapshot.partial,
                report.language
            ),
            crate::output::morning_markdown(&report)?
        );
        text = crate::output::branding::without_footer(&text).to_owned();
        if let Some(error) = &research_error {
            text = fill(words.agent_partial, &[&text, error]);
        }
        if let Some(error) = &impact_error {
            text = fill(words.agent_partial, &[&text, error]);
        }
        let text = fill(words.audit_note, &[&text]);
        let text = crate::output::branding::finish(&text, report.language);
        let text = crate::output::normalize_report_paths(&report, &text)?;
        fs::create_dir_all(&config.report_dir)?;
        let report_path = config
            .report_dir
            .join(format!("{}-{}.md", run_id, profile.project_id));
        crate::atomic_write(&report_path, text.as_bytes())?;
        let complete = research_error.is_none()
            && impact_error.is_none()
            && !report_snapshot.partial
            && pending.deliverable;
        let outcome = if complete {
            "report_written"
        } else {
            "report_partial"
        };
        let transaction = store.connection.unchecked_transaction()?;
        let set_meta = |key: &str, value: &str| -> Result<()> {
            transaction.execute(
                "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
                rusqlite::params![key, value],
            )?;
            Ok(())
        };
        set_meta("last_job", &crate::now())?;
        set_meta("last_report", &report_path.to_string_lossy())?;
        set_meta("last_job_outcome", outcome)?;
        if !force {
            set_meta("last_completed_slot", &completion)?;
        }
        set_meta("last_job_directory", &directory.to_string_lossy())?;
        if complete {
            transaction.execute("DELETE FROM meta WHERE key='last_agent_failure'", [])?;
            set_meta("last_agent_success", &crate::now())?;
        }
        let failure = match (&research_error, &impact_error) {
            (Some(research), Some(impact)) => Some(format!("{research}; {impact}")),
            (Some(error), None) | (None, Some(error)) => Some(error.clone()),
            (None, None) => None,
        };
        if let Some(error) = failure {
            set_meta("last_agent_failure", &error)?;
        }
        transaction.commit()?;
        Ok(
            serde_json::json!({"schema_version":1,"state":outcome,"report":report_path,"slot":slot_key,"research_error":research_error,"impact_error":impact_error,"unattended_sandbox":false,"review_budget_minutes":profile.research.review_budget_minutes,"review_deadline":budget_deadline,"review_budget_exhausted":budget_deadline.is_some_and(|end| Utc::now() >= end)}),
        )
    })();
    if let Err(error) = result {
        if let Err(record_error) = record_job_failure(&store, &directory) {
            return Err(error.context(format!(
                "failed to record scheduled job failure: {record_error:#}"
            )));
        }
        return Err(error);
    }
    result
}

fn record_job_failure(store: &Store, directory: &Path) -> Result<()> {
    let transaction = store.connection.unchecked_transaction()?;
    for (key, value) in [
        ("last_job", crate::now()),
        ("last_job_outcome", "failed".to_owned()),
    ] {
        transaction.execute(
            "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
            rusqlite::params![key, value],
        )?;
    }
    if directory.is_dir() {
        transaction.execute(
            "INSERT OR REPLACE INTO meta VALUES ('last_job_directory',?1)",
            [directory.to_string_lossy().as_ref()],
        )?;
    } else {
        transaction.execute("DELETE FROM meta WHERE key='last_job_directory'", [])?;
    }
    transaction.commit()?;
    Ok(())
}
