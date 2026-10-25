use anyhow::{Context, Result};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub struct ProcessResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}
struct ProcessGuard(std::process::Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if let Ok(raw_pid) = i32::try_from(self.0.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(raw_pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[derive(Clone, Copy)]
enum ProcessKind {
    IsolatedTool,
    Agent,
    SandboxRuntime,
}
pub fn run_sandbox_runtime(
    command: &mut Command,
    seconds: u64,
    max_output: u64,
) -> Result<ProcessResult> {
    run_process(
        command,
        seconds,
        max_output,
        ProcessKind::SandboxRuntime,
        None,
    )
}
pub fn run_bounded(command: &mut Command, seconds: u64, max_output: u64) -> Result<ProcessResult> {
    run_process(
        command,
        seconds,
        max_output,
        ProcessKind::IsolatedTool,
        None,
    )
}
pub fn run_bounded_agent(
    command: &mut Command,
    seconds: u64,
    max_output: u64,
) -> Result<ProcessResult> {
    run_process(command, seconds, max_output, ProcessKind::Agent, None)
}
pub fn run_agent_with_input(
    command: &mut Command,
    seconds: u64,
    max_output: u64,
    input: &[u8],
) -> Result<ProcessResult> {
    run_process(
        command,
        seconds,
        max_output,
        ProcessKind::Agent,
        Some(input),
    )
}
fn run_process(
    command: &mut Command,
    seconds: u64,
    max_output: u64,
    kind: ProcessKind,
    input: Option<&[u8]>,
) -> Result<ProcessResult> {
    #[cfg(not(target_os = "linux"))]
    let _ = kind;
    #[cfg(target_os = "linux")]
    let agent = matches!(kind, ProcessKind::Agent);
    #[cfg(target_os = "linux")]
    let sandbox_runtime = matches!(kind, ProcessKind::SandboxRuntime);
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut bounded = Command::new("prlimit");
        bounded.args([
            if agent {
                "--as=34359738368"
            } else if sandbox_runtime {
                "--as=8589934592"
            } else {
                "--as=2147483648"
            },
            // Agent state files and VM disks have separate quotas from captured output.
            if agent {
                "--fsize=unlimited"
            } else if sandbox_runtime {
                "--fsize=3221225472"
            } else {
                "--fsize=67108864"
            },
            if agent {
                "--nofile=1024"
            } else if sandbox_runtime {
                "--nofile=256"
            } else {
                "--nofile=128"
            },
            if agent { "--cpu=1800" } else { "--cpu=120" },
            "--",
        ]);
        bounded.arg(command.get_program()).args(command.get_args());
        bounded.env_clear();
        for (key, value) in command.get_envs() {
            if let Some(value) = value {
                bounded.env(key, value);
            }
        }
        if let Some(directory) = command.get_current_dir() {
            bounded.current_dir(directory);
        }
        bounded
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let stdin = match input {
        Some(bytes) => {
            let mut file = tempfile::tempfile()?;
            file.write_all(bytes)?;
            file.seek(SeekFrom::Start(0))?;
            Stdio::from(file)
        }
        None => Stdio::null(),
    };
    command
        .stdin(stdin)
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    let mut child = ProcessGuard(
        command
            .spawn()
            .context("cannot start required executable")?,
    );
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(seconds)
            || stdout.metadata()?.len() > max_output
            || stderr.metadata()?.len() > max_output
        {
            timed_out = true;
            #[cfg(unix)]
            {
                let pid = nix::unistd::Pid::from_raw(i32::try_from(child.0.id())?);
                let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
            }
            let _ = child.0.kill();
            break child.0.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    #[cfg(unix)]
    {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.0.id())?);
        let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
    }
    timed_out |= stdout.metadata()?.len() > max_output || stderr.metadata()?.len() > max_output;
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(max_output).read_to_end(&mut out)?;
    stderr.take(max_output).read_to_end(&mut err)?;
    Ok(ProcessResult {
        success: status.success() && !timed_out,
        exit_code: status.code(),
        stdout: out,
        stderr: err,
        timed_out,
    })
}
