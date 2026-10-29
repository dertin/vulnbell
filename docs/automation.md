# Scheduled runs

Each project sets its frequency, time zone, start time, allowed window, runner ID, and Markdown folder. Executable paths and model settings belong to the local runner configuration, not the project schedule.

1. Configure and check a local runner as described in [Local runners](runners.md).
2. Set `schedule: daily`, `weekdays`, or `weekly` in the profile.
3. Create the schedule using that profile's UUID, runner ID, and absolute report directory.
4. Register the job with the system scheduler and check the report from its first run.

```json
{
  "schema_version": 2,
  "project_id": "<profile UUID>",
  "runner": "default",
  "timezone": "America/Montevideo",
  "at": "08:00",
  "window_minutes": 180,
  "frequency": "daily",
  "report_dir": "/absolute/path/to/reports"
}
```

Use `vulnbell schema schedule --json` for the exact project contract. `vulnbell runners list --json` shows the runner IDs available on the current machine.

Linux can install and inspect a user-level systemd timer directly:

```sh
vulnbell schedule install --project /absolute/path/vulnbell.yaml --from schedule.json
vulnbell schedule status --project /absolute/path/vulnbell.yaml
vulnbell schedule remove --project /absolute/path/vulnbell.yaml
```

After moving a profile, rerun `schedule install` with the new path; it rewrites the project's units. `remove` disables the timer and deletes only units managed for that project. Run history and reports remain.

On macOS, configure launchd to call the following command. On Windows, configure Task Scheduler to call it. Use an absolute path to both the executable and profile.

```sh
vulnbell run --project /absolute/path/vulnbell.yaml
```

Native job installation is included for Linux. VulnBell does not create the launchd or Task Scheduler job. The same project schedule and execution window are enforced when the native scheduler calls `run`.

Run and inspect the monitor at any time:

```sh
vulnbell run --project /absolute/path/vulnbell.yaml --now
vulnbell status --json
```

`weekdays` runs Monday to Friday. `weekly` runs on Monday. Each project can use a different time.

The timer runs as soon as possible within the window. If the computer misses the whole window, that run is skipped. Runs for the same project cannot overlap. A second command waits up to 120 seconds for the project lock; set `VULNBELL_LOCK_WAIT_SECONDS` to change it. Expired periods are not replayed. VulnBell does not wake the computer or promise to run before login.

The job scans, completes pending discovery, researches upstream activity in bounded pages, validates and imports results, and writes a report. Workspace extraction has no tools; public discovery receives component identities without workspace text. File queues and source continuations persist across runs. Only a completed source review advances its time checkpoint. An agent failure leaves a Markdown report marked as partial. `vulnbell status` shows every registered project, discovery progress, runner availability, timer health, completed or skipped runs, failures, and the latest report. `schedule status` shows the same persisted details for one profile.

Reports are written below the configured absolute `report_dir`, using one unique Markdown filename per run. The `report` field returned by `vulnbell run` and `last_report` from `vulnbell status` contain the exact path. Private job files are stored in `<data directory>/<UUID>/jobs/`. The job does not change project code, send messages, or approve active tests.
