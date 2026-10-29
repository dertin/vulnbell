mod cli;

use anyhow::{Context, Result, bail};
use clap::Parser;
use cli::{Cli, Commands, RunnerCommands, Sandbox, Skills, ToolCommands, WorkspaceCommands};
use std::{fs, io::Write};
use vulnbell::{
    model::Verdict,
    profile::{self, Profile},
    store::Store,
    tools::{cases, draft, hits, queue, workspace},
};

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
                "scope-batch" => {
                    serde_json::to_value(schemars::schema_for!(vulnbell::tools::cases::ScopeBatch))?
                }
                "handoff-batch" => serde_json::to_value(schemars::schema_for!(
                    vulnbell::tools::cases::HandoffBatch
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
            clear_validation_blocker,
            blocker_kind,
            instance,
            ..
        } => {
            let (_, mut store) = store_for(&project)?;
            if release_tree.is_some()
                || evidence_url.is_some()
                || evidence_file.is_some()
                || validation_blocker.is_some()
                || clear_validation_blocker.is_some()
            {
                store.ensure_workspace_current()?;
            }
            let mut case = store.case(&id)?;
            let evidence_before = case.evidence.len();
            let modifies = release_tree.is_some()
                || evidence_url.is_some()
                || evidence_file.is_some()
                || validation_blocker.is_some();
            let modifies = modifies || clear_validation_blocker.is_some();
            if instance.is_some()
                && validation_blocker.is_none()
                && clear_validation_blocker.is_none()
            {
                anyhow::bail!(
                    "--instance requires --validation-blocker or --clear-validation-blocker"
                );
            }
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
                let mut evidence = store.record_evidence(
                    &response.body,
                    "agent_web",
                    Some(url.clone()),
                    vulnbell::model::EvidenceKind::Context,
                )?;
                let advisory = vulnbell::sources::case_repository_advisory(
                    &case,
                    &url,
                    &response.body,
                    &evidence,
                );
                if let Some((advisory_id, claims)) = advisory {
                    if !claims.is_empty() {
                        evidence.kind = vulnbell::model::EvidenceKind::Advisory;
                    }
                    let existing: Vec<_> = case
                        .claims
                        .iter()
                        .filter(|old| old.source == "github_repository" && old.id == advisory_id)
                        .collect();
                    let changed = existing.len() != claims.len()
                        || claims.iter().any(|claim| {
                            !existing.iter().any(|old| {
                                old.instance_id == claim.instance_id
                                    && old.evidence.sha256 == claim.evidence.sha256
                                    && old.applicability == claim.applicability
                            })
                        });
                    if changed {
                        case.claims.retain(|old| {
                            !(old.source == "github_repository" && old.id == advisory_id)
                        });
                        case.claims.extend(claims);
                        case.facts_sha256 = vulnbell::digest(
                            format!("{}:{}", case.facts_sha256, evidence.sha256).as_bytes(),
                        );
                        case.decision = vulnbell::model::Decision::Review;
                        case.applicability = vulnbell::model::Applicability::Unknown;
                        case.verification = vulnbell::model::Verification::Inconclusive;
                    }
                }
                if let Some(old) = case.evidence.iter_mut().find(|old| old.id == evidence.id) {
                    if evidence.kind == vulnbell::model::EvidenceKind::Advisory {
                        *old = evidence;
                    }
                } else {
                    case.evidence.push(evidence);
                }
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
            if let Some(reason) = clear_validation_blocker {
                case = vulnbell::sandbox::clear_blocker(
                    &mut store,
                    &id,
                    instance.as_deref(),
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
            Sandbox::Capabilities { project } => {
                let limits = match project {
                    Some(path) => profile::load(&path)?.sandbox,
                    None => profile::SandboxLimits::default(),
                };
                emit(&vulnbell::sandbox::capabilities(limits))?;
            }
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
        ToolCommands::Evaluate { from, top } => {
            let bytes = vulnbell::read_limited(&from, 16 * 1024 * 1024)?;
            let corpus: vulnbell::tools::evaluate::Corpus = serde_json::from_slice(&bytes)?;
            emit(&vulnbell::tools::evaluate::evaluate(corpus, top)?)?;
            Ok(0)
        }
        ToolCommands::Hits {
            project,
            raw,
            decisions,
            output,
            offline,
            recheck,
            upstream,
        } => {
            let (_, store) = store_for(&project)?;
            let decisions = decisions
                .as_deref()
                .map(draft::ResearchDecisions::load)
                .transpose()?;
            let prepared =
                hits::prepare_for_upstream(&store, &raw, offline, recheck, upstream.as_deref())?;
            let packet = hits::packet_with_recheck(&prepared, decisions.as_ref(), recheck);
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
            recheck,
            upstream,
        } => {
            let (_, mut store) = store_for(&project)?;
            let decisions = draft::ResearchDecisions::load(&decisions)?;
            let prepared =
                hits::prepare_for_upstream(&store, &raw, offline, recheck, upstream.as_deref())?;
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
        ToolCommands::Scope { project, from } => {
            let (_, mut store) = store_for(&project)?;
            let batch = cases::load_scope(&from)?;
            let outcomes = cases::apply_scope(&mut store, &batch, batch_base(&from));
            emit_outcomes(&outcomes)
        }
        ToolCommands::Handoff { project, from } => {
            let (_, mut store) = store_for(&project)?;
            let batch = cases::load_handoff(&from)?;
            let outcomes = cases::apply_handoff(&mut store, &batch, batch_base(&from));
            emit_outcomes(&outcomes)
        }
        ToolCommands::Pending { project, json: _ } => {
            let (_, store) = store_for(&project)?;
            let report = cases::pending(&store)?;
            emit(&report)?;
            Ok(if report.deliverable { 0 } else { 2 })
        }
        ToolCommands::Queue {
            project,
            limit,
            offset,
            unworked,
        } => {
            let (_, store) = store_for(&project)?;
            emit(&queue::list(&store, limit, offset, unworked)?)?;
            Ok(0)
        }
        ToolCommands::Progress {
            project,
            case,
            state,
            next_step,
        } => {
            let (_, store) = store_for(&project)?;
            if state == "history" {
                if next_step.is_some() {
                    bail!("history does not accept a next step");
                }
                emit(&queue::progress_history(&store, &case)?)?;
                return Ok(0);
            }
            let state = match state.as_str() {
                "start" => queue::WorkState::InProgress,
                "reviewed" => queue::WorkState::Reviewed,
                "human_review" => queue::WorkState::HumanReview,
                _ => bail!("unsupported review progress state"),
            };
            emit(&queue::record(&store, &case, state, next_step.as_deref())?)?;
            Ok(0)
        }
        ToolCommands::Groups { project } => {
            if !(2..=20).contains(&project.len()) {
                bail!("provide 2..20 project profiles");
            }
            let mut ids = std::collections::HashSet::new();
            let mut monitors = Vec::new();
            for path in project {
                let (profile, store) = store_for(&path)?;
                if !ids.insert(profile.project_id) {
                    bail!("each project must be unique");
                }
                monitors.push((path.to_string_lossy().into_owned(), store));
            }
            let groups = queue::shared_cases(&monitors)?;
            emit(
                &serde_json::json!({"schema_version": 1, "groups": groups, "notice": "Candidate grouping only; verify artifact identity and each project's build, conditions and evidence before reuse."}),
            )?;
            Ok(0)
        }
        ToolCommands::Duplicates { project } => {
            let (_, store) = store_for(&project)?;
            let groups = queue::duplicate_advisories(&store)?;
            emit(
                &serde_json::json!({"schema_version": 1, "groups": groups, "notice": "Candidate grouping only; verify artifact and project conditions. No cases are merged or closed."}),
            )?;
            Ok(0)
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
