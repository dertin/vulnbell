use reqwest::header::HeaderValue;
use std::{
    ffi::OsStr,
    io::Read,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

pub(crate) struct GitHubCredentials {
    pub(super) header: HeaderValue,
    pub(crate) source: &'static str,
}

pub(crate) fn github_credentials() -> Option<GitHubCredentials> {
    if let Ok(token) = std::env::var("GITHUB_TOKEN")
        && !token.trim().is_empty()
    {
        return credentials(&token, "environment");
    }
    let token = gh_token(OsStr::new("gh"))?;
    credentials(&token, "gh")
}

fn credentials(token: &str, source: &'static str) -> Option<GitHubCredentials> {
    let token = token.trim();
    if token.is_empty()
        || token.len() > 8192
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
    header.set_sensitive(true);
    Some(GitHubCredentials { header, source })
}

fn gh_token(executable: &OsStr) -> Option<String> {
    let mut child = Command::new(executable)
        .args(["auth", "token", "--hostname", "github.com"])
        .env("GH_PROMPT_DISABLED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(8194).read_to_end(&mut bytes).map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return None,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let bytes = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?
        .ok()?;
    if bytes.len() > 8193 {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub(super) fn authenticated_endpoint(url: &url::Url) -> bool {
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port_or_known_default() != Some(443)
    {
        return false;
    }
    let parts: Vec<_> = url.path_segments().into_iter().flatten().collect();
    matches!(parts.as_slice(), ["advisories"] | ["advisories", _])
        || matches!(parts.as_slice(), ["repos", owner, repo, "security-advisories"] if !owner.is_empty() && !repo.is_empty())
        || matches!(parts.as_slice(), ["repos", owner, repo, "security-advisories", _] if !owner.is_empty() && !repo.is_empty())
        || matches!(parts.as_slice(), ["repos", owner, repo, "releases", "latest"] if !owner.is_empty() && !repo.is_empty())
        || matches!(parts.as_slice(), ["repos", owner, repo, "releases", "tags", _] if !owner.is_empty() && !repo.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{authenticated_endpoint, credentials};

    #[test]
    fn credentials_are_validated_and_marked_sensitive() {
        let secret = "synthetic-token";
        let credentials = credentials(secret, "test").unwrap();
        assert!(credentials.header.is_sensitive());
        assert!(!format!("{:?}", credentials.header).contains(secret));
        assert!(super::credentials("bad\ntoken", "test").is_none());
        assert!(super::credentials("", "test").is_none());
    }

    #[test]
    fn credentials_are_limited_to_github_advisory_and_release_endpoints() {
        for value in [
            "https://api.github.com/advisories?cve_id=CVE-2026-1234",
            "https://api.github.com/advisories/GHSA-abcd-1234-wxyz",
            "https://api.github.com/repos/owner/repo/security-advisories?state=published",
            "https://api.github.com/repos/owner/repo/security-advisories/GHSA-abcd-1234-wxyz",
            "https://api.github.com/repos/owner/repo/releases/latest",
            "https://api.github.com/repos/owner/repo/releases/tags/v1.0.0",
        ] {
            assert!(
                authenticated_endpoint(&url::Url::parse(value).unwrap()),
                "{value}"
            );
        }
        for value in [
            "https://api.github.com/user",
            "https://api.github.com/repos/owner/repo/contents/private",
            "https://api.github.com.evil.example/advisories",
            "https://api.github.com:8443/advisories",
            "http://api.github.com/advisories",
        ] {
            assert!(
                !authenticated_endpoint(&url::Url::parse(value).unwrap()),
                "{value}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn gh_credential_is_read_from_a_bounded_pipe_and_failures_are_ignored() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("gh");
        fs::write(&executable, "#!/bin/sh\n[ \"$*\" = 'auth token --hostname github.com' ] || exit 1\nprintf 'synthetic-token\\n'\nprintf 'ignored stderr' >&2\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            super::gh_token(executable.as_os_str()).as_deref(),
            Some("synthetic-token\n")
        );
        fs::write(
            &executable,
            "#!/bin/sh\nprintf 'must-not-be-used'\nexit 1\n",
        )
        .unwrap();
        assert!(super::gh_token(executable.as_os_str()).is_none());
        fs::write(&executable, "#!/bin/sh\nprintf '%09000d' 0\n").unwrap();
        assert!(super::gh_token(executable.as_os_str()).is_none());
    }
}
