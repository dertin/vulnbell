use crate::model::{Case, Snapshot};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, params};
use std::{
    fs,
    path::{Path, PathBuf},
};

const DATABASE_SCHEMA: u32 = 2;
/// Default wait for another command on the same project (override: VULNBELL_LOCK_WAIT_SECONDS).
const LOCK_WAIT_SECONDS: u64 = 120;

pub fn data_root() -> PathBuf {
    if let Some(path) = std::env::var_os("VULNBELL_DATA_DIR") {
        return PathBuf::from(path);
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::user_home().unwrap_or_default().join(".local/share"));
    base.join("vulnbell")
}
pub struct Store {
    pub connection: Connection,
    pub directory: PathBuf,
}
impl Store {
    pub fn open(project_id: &str) -> Result<Self> {
        let directory = project_directory(project_id)?;
        fs::create_dir_all(&directory)?;
        let database = directory.join("state.sqlite");
        let existing = database.exists();
        let connection = if existing {
            Self::open_existing(project_id)?;
            Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_WRITE)?
        } else {
            Connection::open(database)?
        };
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut store = Self {
            connection,
            directory,
        };
        if existing {
            store.check_schema()?;
        }
        store
            .connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        if !existing {
            let transaction = store.connection.transaction()?;
            transaction.execute_batch("
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE snapshots (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE cases (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE history (sequence INTEGER PRIMARY KEY, case_id TEXT NOT NULL, body TEXT NOT NULL, recorded_at TEXT NOT NULL);
            CREATE TABLE alerts (id TEXT PRIMARY KEY, sent_at TEXT NOT NULL);
            CREATE TABLE research_cursors (upstream TEXT PRIMARY KEY, reviewed_until TEXT NOT NULL);
            CREATE TABLE research_progress (upstream TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE research_events (key TEXT PRIMARY KEY, upstream TEXT NOT NULL, external_id TEXT NOT NULL, url TEXT NOT NULL, content_sha256 TEXT NOT NULL, updated_at TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE research_reviews (sequence INTEGER PRIMARY KEY, body TEXT NOT NULL, recorded_at TEXT NOT NULL);
            CREATE TABLE inventory_cache (key TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE discovery_walk (scope TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, cursor TEXT NOT NULL, stamp TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(scope,root,path));
            CREATE TABLE discovery_files (id TEXT PRIMARY KEY, scope TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, stamp TEXT NOT NULL, offset INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL);
            CREATE TABLE discovery_packages (id TEXT PRIMARY KEY, scope TEXT NOT NULL, file_id TEXT NOT NULL, start INTEGER NOT NULL, end INTEGER NOT NULL, sha256 TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE discovery_sources (scope TEXT NOT NULL, instance_id TEXT NOT NULL, fingerprint TEXT NOT NULL, checked_at TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(scope,instance_id));
            CREATE TABLE discovery_documents (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE discovery_history (sequence INTEGER PRIMARY KEY, scope TEXT NOT NULL, phase TEXT NOT NULL, body TEXT NOT NULL, recorded_at TEXT NOT NULL);
            CREATE TABLE cache (key TEXT PRIMARY KEY, body BLOB NOT NULL, etag TEXT, fetched_at INTEGER NOT NULL);")?;
            transaction.pragma_update(None, "user_version", DATABASE_SCHEMA)?;
            transaction.commit()?;
        }
        fs::create_dir_all(store.directory.join("evidence"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&store.directory, fs::Permissions::from_mode(0o700))?;
        }
        Ok(store)
    }
    pub fn open_existing(project_id: &str) -> Result<Self> {
        let directory = project_directory(project_id)?;
        let database = directory.join("state.sqlite");
        if !database.is_file() {
            bail!("project state database is missing");
        }
        let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let store = Self {
            connection,
            directory,
        };
        store.check_schema()?;
        Ok(store)
    }
    pub fn register_project(&self, name: &str, profile_path: &Path) -> Result<()> {
        let profile_path = profile_path.canonicalize()?;
        self.set_meta("project_name", name)?;
        self.set_meta("profile_path", &profile_path.to_string_lossy())
    }
    pub fn lock(&self) -> Result<fs::File> {
        let wait = std::env::var("VULNBELL_LOCK_WAIT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(LOCK_WAIT_SECONDS);
        self.lock_within(wait)
    }
    /// Waits up to `wait` seconds for the project lock held by another command.
    pub fn lock_within(&self, wait: u64) -> Result<fs::File> {
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.directory.join("scan.lock"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
        loop {
            match fs2::FileExt::try_lock_exclusive(&lock) {
                Ok(()) => return Ok(lock),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error).context(format!(
                        "project is already running; waited {wait}s for the project lock"
                    )));
                }
            }
        }
    }
    pub fn record_evidence(
        &self,
        bytes: &[u8],
        source: &str,
        url: Option<String>,
        kind: crate::model::EvidenceKind,
    ) -> Result<crate::model::Evidence> {
        // Remote JSON is stored canonically so a feed's key order cannot change case facts.
        let canonical = url.as_ref().and_then(|_| crate::canonical_json(bytes));
        let bytes = canonical.as_deref().unwrap_or(bytes);
        let hash = crate::digest(bytes);
        let path = self.directory.join("evidence").join(&hash);
        if !path.exists() {
            crate::atomic_write(&path, bytes)?;
        }
        Ok(crate::model::Evidence {
            id: format!("EV-{}", &hash[..24]),
            sha256: hash,
            source: source.into(),
            url,
            observed_at: crate::now(),
            kind,
        })
    }
    pub fn evidence_exists(&self, evidence: &crate::model::Evidence) -> Result<bool> {
        let bytes = crate::read_limited(
            &self.directory.join("evidence").join(&evidence.sha256),
            32 * 1024 * 1024,
        )?;
        Ok(crate::digest(&bytes) == evidence.sha256)
    }
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO meta VALUES (?1,?2)",
            params![key, value],
        )?;
        Ok(())
    }
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .connection
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }
    pub fn save_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO snapshots VALUES (?1,?2)",
            params![snapshot.id, serde_json::to_string(snapshot)?],
        )?;
        // `cases` is the current projection; immutable snapshots/history retain retired and merged cases.
        transaction.execute("DELETE FROM cases", [])?;
        for case in &snapshot.cases {
            transaction.execute(
                "INSERT OR REPLACE INTO cases VALUES (?1,?2)",
                params![case.case_id, serde_json::to_string(case)?],
            )?;
            transaction.execute(
                "INSERT INTO history(case_id,body,recorded_at) VALUES (?1,?2,?3)",
                params![case.case_id, serde_json::to_string(case)?, crate::now()],
            )?;
        }
        transaction.execute(
            "INSERT OR REPLACE INTO meta VALUES ('last_snapshot',?1)",
            [&snapshot.id],
        )?;
        transaction.commit()?;
        Ok(())
    }
    pub fn case(&self, id: &str) -> Result<Case> {
        use rusqlite::OptionalExtension;
        let active: Option<String> = self
            .connection
            .query_row("SELECT body FROM cases WHERE id=?1", [id], |row| row.get(0))
            .optional()?;
        let body = match active {
            Some(body) => body,
            None => self
                .connection
                .query_row(
                    "SELECT body FROM history WHERE case_id=?1 ORDER BY sequence DESC LIMIT 1",
                    [id],
                    |row| row.get(0),
                )
                .context("case not found in this project's active state or history")?,
        };
        Ok(serde_json::from_str(&body)?)
    }
    pub fn cases(&self) -> Result<Vec<Case>> {
        let mut statement = self
            .connection
            .prepare("SELECT body FROM cases ORDER BY id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut cases = Vec::new();
        for row in rows {
            cases.push(serde_json::from_str(&row?)?);
        }
        Ok(cases)
    }
    pub fn latest(&self) -> Result<Snapshot> {
        let id = self.meta("last_snapshot")?.context("no scan yet")?;
        let body: String =
            self.connection
                .query_row("SELECT body FROM snapshots WHERE id=?1", [id], |row| {
                    row.get(0)
                })?;
        Ok(serde_json::from_str(&body)?)
    }
    pub fn save_case(&mut self, case: &Case) -> Result<()> {
        let body = serde_json::to_string(case)?;
        let current_snapshot = self.meta("last_snapshot")?;
        let active = current_snapshot
            .as_deref()
            .is_none_or(|snapshot| snapshot == case.snapshot_id);
        let transaction = self.connection.transaction()?;
        if active {
            transaction.execute(
                "INSERT OR REPLACE INTO cases VALUES (?1,?2)",
                params![case.case_id, body],
            )?;
        }
        transaction.execute(
            "INSERT INTO history(case_id,body,recorded_at) VALUES (?1,?2,?3)",
            params![case.case_id, body, crate::now()],
        )?;
        transaction.commit()?;
        Ok(())
    }
    pub fn check_schema(&self) -> Result<()> {
        let version: u32 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != DATABASE_SCHEMA {
            bail!(
                "unsupported database schema {version}; expected {DATABASE_SCHEMA}. Create a new monitor with a new project ID; existing state was not changed"
            );
        }
        Ok(())
    }
}

fn project_directory(project_id: &str) -> Result<PathBuf> {
    let _: uuid::Uuid = project_id.parse()?;
    let directory = data_root().join(project_id);
    if directory.is_symlink()
        || [
            "evidence",
            "state.sqlite",
            "state.sqlite-wal",
            "state.sqlite-shm",
            "scan.lock",
            "job.lock",
        ]
        .iter()
        .any(|name| directory.join(name).is_symlink())
    {
        bail!("refusing symlink in project state directory");
    }
    Ok(directory)
}
