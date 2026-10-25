use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};
use vulnbell::{
    model::Verdict,
    profile::{self, Profile},
    store::Store,
};

#[derive(Parser)]
#[command(
    version,
    about = "Agent-first upstream security monitoring; explicit evidence and coverage"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Install the embedded, version-aligned Agent Skill without overwriting user changes.
    Skills {
        #[command(subcommand)]
        command: Skills,
    },
    /// Inspect CLI, skill, credentials, sandbox and scheduler capabilities.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// List monitored projects, scans, schedules, skipped runs and reports.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Create a valid empty project; does not require a local workspace.
    Init {
        #[arg(long)]
        output: PathBuf,
    },
    /// Print a versioned JSON Schema generated from the Rust contract.
    Schema {
        #[arg(value_parser=["profile","verdict","case","test","attestation","impact","report","research","snapshot","schedule","status"])]
        contract: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate YAML and semantic rules locally; no network calls.
    Validate {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Resolve inventory and query sources; never execute project code. Exit 2 means partial coverage.
    Scan {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        offline: bool,
    },
    /// List audited cases from the latest project state.
    Inbox {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Open an evidence-bound case; optionally acquire an exact release tree in isolated Git.
    Case {
        id: String,
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        release_tree: Option<String>,
        /// Fetch and register a public research link as context, never as an attestation.
        #[arg(long)]
        evidence_url: Option<String>,
        /// Register a reviewed local note or result as evidence; do not include secrets or raw workspaces.
        #[arg(long)]
        evidence_file: Option<PathBuf>,
        /// Record why local validation is blocked; this is context, never proof of safety.
        #[arg(long, requires = "instance")]
        validation_blocker: Option<String>,
        #[arg(long, requires = "validation_blocker")]
        instance: Option<String>,
    },
    /// Execute an explicitly authorized test in Microsandbox; no fallback to host execution.
    Verify {
        id: String,
        #[arg(long)]
        project: PathBuf,
        #[arg(long = "case")]
        test: PathBuf,
        #[arg(long)]
        authorize: bool,
    },
    /// Answer a fixed, evidence-bound questionnaire about project impact.
    Impact {
        id: String,
        #[arg(long)]
        project: PathBuf,
        /// JSON answers matching schema impact. Without this option, prints the questions.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Apply a verdict against registered evidence and current case facts.
    Triage {
        id: String,
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        from: PathBuf,
    },
    /// Export the current inventory, cases and source coverage.
    Report {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long,default_value="manager",value_parser=["manager","cyber","audit"])]
        audience: String,
    },
    /// Configure or inspect a real user-level daily scheduler; install runs the service once.
    Schedule {
        #[arg(value_parser=["install","status"])]
        action: String,
        #[arg(long)]
        project: PathBuf,
        /// Per-project ScheduleConfig JSON; schema is available through schema schedule.
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Run the configured local agent inside the current schedule window; --now is an explicit test.
    Run {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        now: bool,
    },
    /// Give the local agent review windows/seen events, or import its upstream observations.
    Research {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        from: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Acquire checksummed official guest artifacts; no guest/project code runs on the host.
    Sandbox {
        #[command(subcommand)]
        command: Sandbox,
    },
}
#[derive(Subcommand)]
enum Skills {
    Install {
        #[arg(long, default_value="auto",value_parser=["auto","universal","codex","opencode"])]
        host: String,
        #[arg(long)]
        directory: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum Sandbox {
    /// Copy selected files into a hashed archive; never run project code on the host.
    Stage {
        #[arg(long)]
        source: PathBuf,
        #[arg(long = "file", required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        directory: PathBuf,
    },
    Prepare {
        /// Digest-pinned official OCI toolchain image; defaults to Alpine.
        #[arg(long)]
        image: Option<String>,
    },
    Status,
}
fn emit(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn store_for(path: &std::path::Path) -> Result<(Profile, Store)> {
    let profile = profile::load(path)?;
    let store = Store::open(&profile.project_id.to_string())?;
    Ok((profile, store))
}
fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Skills {
            command: Skills::Install { host, directory },
        } => {
            let directories = match directory {
                Some(directory) => vec![directory],
                None => vulnbell::skills::skill_directories(&host)?,
            };
            for directory in &directories {
                vulnbell::skills::install_skill(directory)?;
            }
            emit(
                &serde_json::json!({"schema_version":1,"version":env!("CARGO_PKG_VERSION"),"installed":directories}),
            )?;
        }
        Commands::Doctor { .. } => emit(&vulnbell::operations::doctor()?)?,
        Commands::Status { json } => {
            let report = vulnbell::operations::status()?;
            if json {
                emit(&report)?;
            } else {
                print!("{}", vulnbell::operations::status_markdown(&report));
            }
        }
        Commands::Init { output } => {
            if output.exists() {
                bail!("refusing to overwrite existing profile");
            }
            let profile = Profile {
                schema: 1,
                project_id: uuid::Uuid::new_v4(),
                name: "my-monitor".into(),
                workspaces: Vec::new(),
                components: Vec::new(),
                research: Default::default(),
                schedule: None,
                alerts: Default::default(),
            };
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            file.write_all(serde_saphyr::to_string(&profile)?.as_bytes())?;
            file.sync_all()?;
            let store = Store::open(&profile.project_id.to_string())?;
            store.register_project(&profile.name, &output)?;
            emit(
                &serde_json::json!({"schema_version":1,"project_id":profile.project_id,"profile":output,"warning":"empty_scope: add components/workspaces before scan"}),
            )?;
        }
        Commands::Schema { contract, .. } => {
            let schema = match contract.as_str() {
                "profile" => profile::schema(),
                "verdict" => serde_json::to_value(schemars::schema_for!(Verdict))?,
                "case" => serde_json::to_value(schemars::schema_for!(vulnbell::model::Case))?,
                "test" => serde_json::to_value(schemars::schema_for!(vulnbell::sandbox::TestSpec))?,
                "attestation" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::sandbox::Attestation))?
                }
                "impact" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::impact::ImpactSubmission))?
                }
                "schedule" => serde_json::to_value(schemars::schema_for!(
                    vulnbell::scheduler::ScheduleConfig
                ))?,
                "research" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::research::ResearchBatch))?
                }
                "report" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::output::MorningReport))?
                }
                "snapshot" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::model::Snapshot))?
                }
                "status" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::operations::StatusReport))?
                }
                _ => bail!("unknown schema"),
            };
            emit(&schema)?;
        }
        Commands::Validate { path, .. } => {
            let bytes = vulnbell::read_limited(&path, 1024 * 1024)?;
            let parsed: std::result::Result<Profile, _> = vulnbell::parse_yaml(&bytes);
            match parsed {
                Ok(profile) => {
                    let result = profile::validate(&profile);
                    emit(&result)?;
                    if !result.valid {
                        return Ok(1);
                    }
                }
                Err(error) => {
                    emit(
                        &serde_json::json!({"schema_version":1,"valid":false,"errors":[{"pointer":"/","code":"invalid_profile","message":error.to_string(),"location":error.location().map(|location|serde_json::json!({"line":location.line(),"column":location.column()}))}],"warnings":[]}),
                    )?;
                    return Ok(1);
                }
            }
        }
        Commands::Scan {
            project,
            json,
            offline,
        } => {
            let profile = profile::load(&project)?;
            let snapshot = vulnbell::engine::scan(&profile, &project, offline)?;
            if json {
                emit(&snapshot)?;
            } else {
                println!("{}", vulnbell::output::markdown(&snapshot));
            }
            if snapshot.partial {
                return Ok(2);
            }
        }
        Commands::Inbox { project, .. } => {
            let (_, store) = store_for(&project)?;
            emit(&serde_json::json!({"schema_version":1,"cases":store.cases()?}))?;
        }
        Commands::Case {
            id,
            project,
            release_tree,
            evidence_url,
            evidence_file,
            validation_blocker,
            instance,
            ..
        } => {
            let (_, mut store) = store_for(&project)?;
            let mut case = store.case(&id)?;
            if let Some(tag) = release_tree {
                let _lock = store.lock()?;
                let upstream = case
                    .instances
                    .first()
                    .and_then(|instance| instance.upstream.as_deref())
                    .context("case has no repository")?;
                let evidence = vulnbell::upstream::release_tree(upstream, &tag, &store)?;
                case.evidence.extend(evidence);
                store.save_case(&case)?;
            }
            if let Some(url) = evidence_url {
                let _lock = store.lock()?;
                let mut http = vulnbell::network::Http::new(&store, false);
                let response = http.get(&url)?;
                let evidence = store.record_evidence(
                    &response.body,
                    "agent_web",
                    Some(url),
                    vulnbell::model::EvidenceKind::Context,
                )?;
                case.evidence.push(evidence);
                case.updated_at = vulnbell::now();
                store.save_case(&case)?;
            }
            if let Some(path) = evidence_file {
                let _lock = store.lock()?;
                let bytes = vulnbell::read_limited(&path, 1024 * 1024)?;
                let evidence = store.record_evidence(
                    &bytes,
                    "local_impact_evidence",
                    None,
                    vulnbell::model::EvidenceKind::Context,
                )?;
                case.evidence.push(evidence);
                case.updated_at = vulnbell::now();
                store.save_case(&case)?;
            }
            if let Some(reason) = validation_blocker {
                case = vulnbell::sandbox::record_blocker(
                    &mut store,
                    &id,
                    instance
                        .as_deref()
                        .context("instance required for validation blocker")?,
                    &reason,
                )?;
            }
            emit(&case)?;
        }
        Commands::Verify {
            id,
            project,
            test,
            authorize,
        } => {
            let (_, mut store) = store_for(&project)?;
            emit(&vulnbell::sandbox::verify(
                &mut store, &id, &test, authorize,
            )?)?;
        }
        Commands::Impact { id, project, from } => {
            let (_, mut store) = store_for(&project)?;
            if let Some(path) = from {
                let submission: vulnbell::impact::ImpactSubmission =
                    serde_json::from_slice(&vulnbell::read_limited(&path, 1024 * 1024)?)?;
                emit(&vulnbell::impact::assess(&mut store, &id, submission)?)?;
            } else {
                let case = store.case(&id)?;
                emit(&vulnbell::impact::plan(&case))?;
            }
        }
        Commands::Triage { id, project, from } => {
            let (_, mut store) = store_for(&project)?;
            let verdict: Verdict =
                serde_json::from_slice(&vulnbell::read_limited(&from, 1024 * 1024)?)?;
            emit(&vulnbell::engine::triage(&mut store, &id, verdict)?)?;
        }
        Commands::Report {
            project,
            json,
            audience,
        } => {
            let (_, store) = store_for(&project)?;
            let mut snapshot = store.latest()?;
            snapshot.cases = store.cases()?;
            if audience == "audit" {
                if json {
                    emit(&snapshot)?;
                } else {
                    println!("{}", vulnbell::output::markdown(&snapshot));
                }
            } else {
                let report = vulnbell::output::morning_report(&snapshot, &store, &audience)?;
                if json {
                    emit(&report)?;
                } else {
                    println!("{}", vulnbell::output::morning_markdown(&report));
                }
            }
        }
        Commands::Run { project, now } => {
            let profile = profile::load(&project)?;
            emit(&vulnbell::scheduler::run(&profile, &project, now)?)?;
        }
        Commands::Schedule {
            action,
            project,
            from,
        } => {
            let profile = profile::load(&project)?;
            emit(&vulnbell::operations::schedule(
                &profile,
                &project,
                &action,
                from.as_deref(),
            )?)?;
        }
        Commands::Research { project, from, .. } => {
            let (_, mut store) = store_for(&project)?;
            if let Some(path) = from {
                let batch: vulnbell::research::ResearchBatch =
                    serde_json::from_slice(&vulnbell::read_limited(&path, 16 * 1024 * 1024)?)?;
                emit(&vulnbell::research::import(&mut store, batch)?)?;
            } else {
                emit(&vulnbell::research::plan(&store)?)?;
            }
        }
        Commands::Sandbox { command } => match command {
            Sandbox::Stage {
                source,
                files,
                directory,
            } => emit(&vulnbell::sandbox::staging::stage(
                &source, &files, &directory,
            )?)?,
            Sandbox::Prepare { image } => {
                emit(&vulnbell::sandbox::prepare_image(image.as_deref())?)?
            }
            Sandbox::Status => emit(&vulnbell::sandbox::availability())?,
        },
    }
    Ok(0)
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"schema_version":1,"error":{"code":"operation_failed","message":error.to_string()}})
            );
            std::process::exit(1);
        }
    }
}
