use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Agent-first upstream security monitoring; explicit evidence and coverage"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Commands,
}
#[derive(Subcommand)]
pub(super) enum Commands {
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
        #[arg(value_parser=["profile","verdict","case","test","attestation","impact","report","research","discovery","runner","snapshot","schedule","status","decisions","impact-batch","verdict-batch","scope-batch","handoff-batch","items"])]
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
        /// Supersede an incorrect or obsolete blocker, retaining its evidence history.
        #[arg(long, conflicts_with = "validation_blocker")]
        clear_validation_blocker: Option<String>,
        /// Category of the validation blocker. Missing deployment facts are not a blocker.
        #[arg(long, requires = "validation_blocker", value_parser = ["details_undisclosed", "artifact_unavailable", "sandbox_limits", "runtime_unavailable", "authorization_declined"])]
        blocker_kind: Option<String>,
        /// Limit the validation blocker to one instance; by default it applies to every instance.
        #[arg(long)]
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
pub(super) enum ToolCommands {
    /// Evaluate screening and ordering against independently labelled local items.
    Evaluate {
        #[arg(long)]
        from: PathBuf,
        /// Number of top-ranked selected items used for precision/recall.
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
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
        /// Reconsider seen events; use a fresh decisions file for this review.
        #[arg(long)]
        recheck: bool,
        /// Restrict this batch to one upstream from the research plan.
        #[arg(long)]
        upstream: Option<String>,
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
        /// Include seen events using the decisions supplied for this review.
        #[arg(long)]
        recheck: bool,
        /// Restrict this batch to one upstream from the research plan.
        #[arg(long)]
        upstream: Option<String>,
    },
    /// Apply an impact batch; note paths are relative to the batch file.
    Impact {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        from: PathBuf,
    },
    /// Narrow over-broad research cases using reviewed evidence; impact remains open.
    Scope {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        from: PathBuf,
    },
    /// Record an evidence-backed review handoff without asserting a sandbox result.
    Handoff {
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
        /// Output is always JSON; accepted for consistency with other commands.
        #[arg(long)]
        json: bool,
    },
    /// List open cases in a deterministic priority order, with persisted review progress.
    Queue {
        #[arg(long)]
        project: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Hide cases already reviewed for their current facts; they remain open.
        #[arg(long)]
        unworked: bool,
    },
    /// Record a review work interval; this never changes the case verdict or pending status.
    Progress {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        case: String,
        #[arg(long, value_parser = ["start", "reviewed", "human_review", "history"])]
        state: String,
        #[arg(long)]
        next_step: Option<String>,
    },
    /// Find candidate shared upstream cases across monitors without copying project decisions.
    Groups {
        #[arg(long, required = true, num_args = 1)]
        project: Vec<PathBuf>,
    },
    /// Suggest repeated cases with the same advisory, package and resolved version.
    Duplicates {
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
pub(super) enum WorkspaceCommands {
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
pub(super) enum Skills {
    Install {
        #[arg(long, default_value="auto",value_parser=["auto","universal","codex","opencode"])]
        host: String,
        #[arg(long)]
        directory: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
pub(super) enum RunnerCommands {
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
pub(super) enum Sandbox {
    /// Show planning limits and isolation requirements without running a test.
    Capabilities {
        /// Use the limits configured by this profile; defaults otherwise.
        #[arg(long)]
        project: Option<PathBuf>,
    },
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
