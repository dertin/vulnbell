# Scheduled runs

Each project sets its frequency, time zone, start time, allowed window, agent, and Markdown folder. Linux needs working user-level systemd.

1. Set `schedule: daily`, `weekdays`, or `weekly` in the profile.
2. Create the configuration using that profile's UUID and absolute paths.
3. Install the timer and check the report from its first run.

```json
{
  "schema_version": 1,
  "project_id": "<profile UUID>",
  "agent": "codex",
  "agent_executable": "/absolute/path/to/codex",
  "timezone": "America/Montevideo",
  "at": "08:00",
  "window_minutes": 180,
  "frequency": "daily",
  "report_dir": "/absolute/path/to/reports"
}
```

For OpenCode, use `agent: "opencode"`, its executable path, and `agent_model: "provider/model"`. See [agents](agents.md) and `vulnbell schema schedule --json`.

```sh
vulnbell schedule install --project /absolute/path/radar.yaml --from schedule.json
vulnbell schedule status --project /absolute/path/radar.yaml
vulnbell run --project /absolute/path/radar.yaml --now
vulnbell status --json
```

`weekdays` runs Monday to Friday. `weekly` runs on Monday. Each project can use a different time.

The timer runs as soon as possible within the window. If the computer misses the whole window, that run is skipped. Runs for the same project cannot overlap. Expired periods are not replayed. VulnBell does not wake the computer or promise to run before login.

The job scans, researches upstream activity, validates and imports the results, and writes a report. An agent failure leaves a Markdown report marked as partial and keeps earlier checkpoints. `vulnbell status` shows every registered project, timer health, completed or skipped runs, failures, and the latest report. `schedule status` shows the same persisted details for one profile.

Private job files are stored in `<data directory>/<UUID>/jobs/`. The job does not change project code, send messages, or approve active tests. Other schedulers can call `run`; VulnBell does not install them automatically.
