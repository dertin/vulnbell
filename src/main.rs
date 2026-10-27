use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::{fs, io::Write, path::PathBuf};
use vulnbell::{
    model::Verdict,
    profile::{self, Profile},
    store::Store,
    tools::{cases, draft, hits, workspace},
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
        #[arg(value_parser=["profile","verdict","case","test","attestation","impact","report","research","discovery","runner","snapshot","schedule","status","decisions","impact-batch","verdict-batch","items"])]
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
        /// Record why a needed sandbox check cannot run; this is context, never proof of safety.
        #[arg(long, requires = "blocker_kind")]
        validation_blocker: Option<String>,
        /// Category of the validation blocker. Missing deployment facts are not a blocker.
        #[arg(long, requires = "validation_blocker", value_parser = ["details_undisclosed", "artifact_unavailable", "sandbox_limits", "runtime_unavailable", "authorization_declined"])]
        blocker_kind: Option<String>,
        /// Limit the validation blocker to one instance; by default it applies to every instance.
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
    /// Configure and verify local unattended agent adapters.
    Runners {
        #[command(subcommand)]
        command: RunnerCommands,
    },
    /// Configure, inspect or remove a user-level scheduler; install runs the service once and
    /// rewrites this project's units, so rerun it after moving the profile.
    Schedule {
        #[arg(value_parser=["install","status","remove"])]
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
        #[arg(long, default_value = "")]
        after: String,
        #[arg(long, default_value_t = 1)]
        limit: usize,
        /// Review this upstream (or `all`) again from `--since`, after the screening method changed.
        #[arg(long, requires = "since", conflicts_with = "from")]
        reopen: Option<String>,
        /// RFC3339 start of the reopened review window.
        #[arg(long, requires = "reopen")]
        since: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Resume general discovery, import observations, or acquire public source evidence.
    Discovery {
        #[arg(long)]
        project: PathBuf,
        #[arg(long, conflicts_with = "evidence_url")]
        from: Option<PathBuf>,
        #[arg(long)]
        evidence_url: Option<String>,
        #[arg(long,conflicts_with_all=["from","evidence_url"])]
        gaps: bool,
        /// Reopen a reviewed workspace-relative file so its packages are reviewed again.
        #[arg(long,conflicts_with_all=["from","evidence_url","gaps"])]
        reopen: Option<String>,
        /// Map pending components from public registry records; `--limit` counts packages (1..500).
        #[arg(long,conflicts_with_all=["from","evidence_url","gaps","reopen"])]
        map_registries: bool,
        #[arg(long, requires = "map_registries")]
        offline: bool,
        #[arg(long, requires = "gaps", default_value = "")]
        after: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Acquire checksummed official guest artifacts; no guest/project code runs on the host.
    Sandbox {
        #[command(subcommand)]
        command: Sandbox,
    },
    /// Local helpers for the daily review: screen fetched tracker responses, draft research
    /// batches from decisions, and apply impact answers and verdicts in bulk.
    Tools {
        #[command(subcommand)]
        command: ToolCommands,
    },
}
#[derive(Subcommand)]
enum ToolCommands {
    /// Screen the responses in a run's raw directory; list missing fetches and items to decide.
    /// Exit 2 means responses are missing or unreadable.
    Hits {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        raw: PathBuf,
        /// Decisions file; items with a current decision are not listed again.
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// Review packet path; stdout receives only the summary.
        #[arg(long)]
        output: PathBuf,
        /// Resolve cited advisories from the local cache only.
        #[arg(long)]
        offline: bool,
    },
    /// Build the research batch from the screened items, the deterministic rules and the
    /// decisions file.
    Draft {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        raw: PathBuf,
        #[arg(long)]
        decisions: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Accept missing responses and undecided items; their sources stay partial.
        #[arg(long)]
        partial: bool,
        /// Import the batch after writing it.
        #[arg(long)]
        import: bool,
        #[arg(long)]
        offline: bool,
    },
    /// Apply an impact batch; note paths are relative to the batch file.
    Impact {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        from: PathBuf,
    },
    /// Apply a verdict batch; note paths are relative to the batch file.
    Triage {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        from: PathBuf,
    },
    /// List what still blocks the daily report. Exit 2 means it is not deliverable yet.
    Pending {
        #[arg(long)]
        project: PathBuf,
    },
    /// Create the monitor's folders in a VulnBell workspace.
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommands,
    },
}
#[derive(Subcommand)]
enum WorkspaceCommands {
    Init {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        monitor: String,
        /// Run day (YYYY-MM-DD); defaults to today in UTC.
        #[arg(long)]
        day: Option<String>,
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
enum RunnerCommands {
    /// Save a typed runner configuration in the local VulnBell data directory.
    Configure {
        #[arg(long)]
        from: PathBuf,
    },
    /// List locally configured runners without starting them.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Verify the configured client version and effective capability policy.
    Check {
        id: String,
        /// Also run one public web research probe through the isolated runner (uses the model).
        #[arg(long)]
        live: bool,
        #[arg(long)]
        json: bool,
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
    print(&serde_json::to_string_pretty(value)?)
}
/// A reader that closes the pipe early (`| head`) already received what it asked for; the
/// command's state is persisted before output.
fn print(text: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{text}").and_then(|()| stdout.flush()) {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        result => Ok(result?),
    }
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
                discovery: Default::default(),
                research: Default::default(),
                schedule: None,
                alerts: Default::default(),
                report: Default::default(),
                sandbox: Default::default(),
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
                "discovery" => serde_json::to_value(schemars::schema_for!(
                    vulnbell::discovery::DiscoveryBatch
                ))?,
                "runner" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::runners::RunnerConfig))?
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
                "decisions" => serde_json::to_value(schemars::schema_for!(
                    vulnbell::tools::draft::ResearchDecisions
                ))?,
                "impact-batch" => serde_json::to_value(schemars::schema_for!(
                    vulnbell::tools::cases::ImpactBatch
                ))?,
                "verdict-batch" => serde_json::to_value(schemars::schema_for!(
                    vulnbell::tools::cases::VerdictBatch
                ))?,
                "items" => serde_json::to_value(schemars::schema_for!(Vec<vulnbell::tools::Item>))?,
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
                print(&vulnbell::output::markdown(&snapshot))?;
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
            blocker_kind,
            instance,
            ..
        } => {
            let (_, mut store) = store_for(&project)?;
            let mut case = store.case(&id)?;
            let evidence_before = case.evidence.len();
            let modifies = release_tree.is_some()
                || evidence_url.is_some()
                || evidence_file.is_some()
                || validation_blocker.is_some();
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
            if let (Some(reason), Some(kind)) = (validation_blocker, blocker_kind) {
                let kind: vulnbell::sandbox::BlockerKind =
                    serde_json::from_value(serde_json::Value::String(kind))?;
                case = vulnbell::sandbox::record_blocker(
                    &mut store,
                    &id,
                    instance.as_deref(),
                    kind,
                    &reason,
                )?;
            }
            if modifies {
                // Agents need only the new references; the full case can exceed their context.
                emit(&serde_json::json!({
                    "schema_version": 1,
                    "case_id": case.case_id,
                    "facts_sha256": case.facts_sha256,
                    "decision": case.decision,
                    "added_evidence": case.evidence.get(evidence_before..).unwrap_or_default(),
                }))?;
            } else {
                emit(&case)?;
            }
        }
        Commands::Verify {
            id,
            project,
            test,
            authorize,
        } => {
            let (profile, mut store) = store_for(&project)?;
            emit(&vulnbell::sandbox::verify(
                &mut store,
                &id,
                &test,
                authorize,
                &profile.sandbox,
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
                emit(&vulnbell::impact::plan(&case, &store))?;
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
                    print(&vulnbell::output::markdown(&snapshot))?;
                }
            } else {
                let report = vulnbell::output::morning_report(&snapshot, &store, &audience)?;
                if json {
                    emit(&report)?;
                } else {
                    print(&vulnbell::output::morning_markdown(&report))?;
                }
            }
        }
        Commands::Run { project, now } => {
            let profile = profile::load(&project)?;
            emit(&vulnbell::scheduler::run(&profile, &project, now)?)?;
        }
        Commands::Runners { command } => match command {
            RunnerCommands::Configure { from } => {
                let config: vulnbell::runners::RunnerConfig =
                    serde_json::from_slice(&vulnbell::read_limited(&from, 64 * 1024)?)?;
                emit(&vulnbell::runners::save(&config)?)?;
            }
            RunnerCommands::List { .. } => emit(&serde_json::json!({
                "schema_version": 1,
                "runners": vulnbell::runners::list()?,
                "adapters": vulnbell::runners::adapter_catalog(),
            }))?,
            RunnerCommands::Check { id, live, .. } => emit(&vulnbell::runners::check(&id, live)?)?,
        },
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
        Commands::Research {
            project,
            from,
            after,
            limit,
            reopen,
            since,
            ..
        } => {
            let (_, mut store) = store_for(&project)?;
            if let (Some(upstream), Some(since)) = (reopen, since) {
                emit(&vulnbell::research::reopen(&mut store, &upstream, &since)?)?;
            } else if let Some(path) = from {
                let batch: vulnbell::research::ResearchBatch =
                    serde_json::from_slice(&vulnbell::read_limited(&path, 16 * 1024 * 1024)?)?;
                emit(&vulnbell::research::import(&mut store, batch)?)?;
            } else {
                emit(&vulnbell::research::plan_page(&store, &after, limit)?)?;
            }
        }
        Commands::Discovery {
            project,
            from,
            evidence_url,
            gaps,
            reopen,
            map_registries,
            offline,
            after,
            limit,
            ..
        } => {
            let (profile, mut store) = store_for(&project)?;
            if map_registries {
                emit(&vulnbell::discovery::map_registries(
                    &profile, &project, &mut store, limit, offline,
                )?)?;
            } else if let Some(relative) = reopen {
                emit(&vulnbell::discovery::reopen(
                    &profile, &project, &mut store, &relative,
                )?)?;
            } else if gaps {
                emit(&vulnbell::discovery::gaps(
                    &profile, &project, &store, &after, limit,
                )?)?;
            } else if let Some(path) = from {
                let batch: vulnbell::discovery::DiscoveryBatch =
                    serde_json::from_slice(&vulnbell::read_limited(&path, 4 * 1024 * 1024)?)?;
                emit(&vulnbell::discovery::import(
                    &profile, &project, &mut store, batch,
                )?)?;
            } else if let Some(url) = evidence_url {
                emit(&vulnbell::discovery::acquire(&profile, &store, &url)?)?;
            } else {
                let _lock = store.lock()?;
                let plan = vulnbell::discovery::plan(&profile, &project, &store, limit)?;
                emit(&plan)?;
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
        Commands::Tools { command } => return run_tool(command),
    }
    Ok(0)
}
fn run_tool(command: ToolCommands) -> Result<i32> {
    match command {
        ToolCommands::Hits {
            project,
            raw,
            decisions,
            output,
            offline,
        } => {
            let (_, store) = store_for(&project)?;
            let decisions = decisions
                .as_deref()
                .map(draft::ResearchDecisions::load)
                .transpose()?;
            let prepared = hits::prepare(&store, &raw, offline)?;
            let packet = hits::packet(&prepared, decisions.as_ref());
            vulnbell::atomic_write(&output, &serde_json::to_vec_pretty(&packet)?)?;
            emit(&serde_json::json!({
                "schema_version": 1,
                "output": output,
                "summary": packet.summary,
                "missing": packet.missing.len(),
                "errors": packet.errors.len(),
            }))?;
            let incomplete = !packet.missing.is_empty() || !packet.errors.is_empty();
            Ok(if incomplete { 2 } else { 0 })
        }
        ToolCommands::Draft {
            project,
            raw,
            decisions,
            output,
            partial,
            import,
            offline,
        } => {
            let (_, mut store) = store_for(&project)?;
            let decisions = draft::ResearchDecisions::load(&decisions)?;
            let prepared = hits::prepare(&store, &raw, offline)?;
            let (batch, summary) = draft::draft(prepared, &decisions, partial)?;
            vulnbell::atomic_write(&output, &serde_json::to_vec_pretty(&batch)?)?;
            let imported = if import {
                Some(vulnbell::research::import(&mut store, batch)?)
            } else {
                None
            };
            emit(&serde_json::json!({
                "schema_version": 1,
                "output": output,
                "summary": summary,
                "imported": imported,
            }))?;
            Ok(0)
        }
        ToolCommands::Impact { project, from } => {
            let (_, mut store) = store_for(&project)?;
            let batch = cases::load_impact(&from)?;
            let outcomes = cases::apply_impact(&mut store, &batch, batch_base(&from));
            emit_outcomes(&outcomes)
        }
        ToolCommands::Triage { project, from } => {
            let (_, mut store) = store_for(&project)?;
            let batch = cases::load_verdicts(&from)?;
            let outcomes = cases::apply_verdicts(&mut store, &batch, batch_base(&from));
            emit_outcomes(&outcomes)
        }
        ToolCommands::Pending { project } => {
            let (_, store) = store_for(&project)?;
            let report = cases::pending(&store)?;
            emit(&report)?;
            Ok(if report.deliverable { 0 } else { 2 })
        }
        ToolCommands::Workspace {
            command:
                WorkspaceCommands::Init {
                    directory,
                    monitor,
                    day,
                },
        } => {
            let day = day.unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
            emit(&workspace::init(&directory, &monitor, &day)?)?;
            Ok(0)
        }
    }
}
fn batch_base(path: &std::path::Path) -> &std::path::Path {
    path.parent().unwrap_or(std::path::Path::new("."))
}
/// Exit 2 when any case was not applied; the others are kept.
fn emit_outcomes(outcomes: &[cases::CaseOutcome]) -> Result<i32> {
    let failed = outcomes.iter().filter(|outcome| !outcome.applied).count();
    emit(&serde_json::json!({
        "schema_version": 1,
        "applied": outcomes.len() - failed,
        "failed": failed,
        "cases": outcomes,
    }))?;
    Ok(if failed > 0 { 2 } else { 0 })
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
