use crate::model::EvidenceKind;
use anyhow::{Context, Result, bail};

fn repository_url(value: &str) -> Result<url::Url> {
    let mut url = crate::profile::public_https_syntax(value)?;
    if url.query().is_some() || url.fragment().is_some() || url.port_or_known_default() != Some(443)
    {
        bail!("repository URL must use HTTPS port 443 without query parameters");
    }
    let path = url.path().trim_matches('/');
    if path.split('/').count() < 2 || path.contains("..") || path.contains('%') {
        bail!("repository must identify an exact public Git path");
    }
    if matches!(
        url.host_str(),
        Some("github.com" | "gitlab.com" | "bitbucket.org")
    ) && !path.ends_with(".git")
    {
        url.set_path(&format!("/{path}.git"));
    }
    Ok(url)
}
pub fn release_tree(
    repository_value: &str,
    tag: &str,
    store: &crate::store::Store,
) -> Result<Vec<crate::model::Evidence>> {
    if tag.is_empty()
        || tag.len() > 200
        || tag.starts_with('-')
        || tag
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("use an explicit release tag");
    }
    let repository = repository_url(repository_value)?;
    let temporary = tempfile::tempdir_in(&store.directory)?;
    let mut command = isolated_git(&repository, temporary.path())?;
    command
        .args([
            "clone",
            "--bare",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--branch",
            tag,
            "--",
            repository.as_str(),
        ])
        .arg(temporary.path().join("tree.git"));
    let result = crate::process::run_bounded(&mut command, 90, 8 * 1024 * 1024)?;
    if !result.success {
        bail!("isolated Git acquisition failed or exceeded limits");
    }
    let mut command = std::process::Command::new("git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("--git-dir")
        .arg(temporary.path().join("tree.git"))
        .args(["rev-parse", "HEAD^{tree}", "HEAD"]);
    let tree = crate::process::run_bounded(&mut command, 10, 4096)?;
    if !tree.success {
        bail!("release tree hash unavailable");
    }
    let metadata = store.record_evidence(
        &tree.stdout,
        "exact_git_release_tree",
        Some(format!("{}#{}", repository.as_str(), tag)),
        EvidenceKind::Context,
    )?;
    let mut archive_command = isolated_git(&repository, temporary.path())?;
    archive_command
        .arg("--git-dir")
        .arg(temporary.path().join("tree.git"))
        .args(["archive", "--format=tar", "HEAD"]);
    let archive = crate::process::run_bounded(&mut archive_command, 30, 32 * 1024 * 1024)?;
    if !archive.success {
        bail!("release archive exceeded limits or failed");
    }
    let source = store.record_evidence(
        &archive.stdout,
        "exact_git_release_archive",
        Some(format!("{}#{}", repository.as_str(), tag)),
        EvidenceKind::Context,
    )?;
    Ok(vec![metadata, source])
}
fn isolated_git(repository: &url::Url, home: &std::path::Path) -> Result<std::process::Command> {
    let (_, url) = crate::network::public_client(repository.as_str())?;
    if url.port_or_known_default() != Some(443) {
        bail!("isolated Git supports HTTPS port 443 only");
    }
    let host = url.host_str().context("missing host")?;
    use std::net::ToSocketAddrs;
    let addresses: Vec<_> = (host, 443).to_socket_addrs()?.collect();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !crate::network::is_public(address.ip()))
    {
        bail!("nonpublic Git destination");
    }
    let resolve = addresses
        .iter()
        .map(|address| address.ip().to_string())
        .collect::<Vec<String>>()
        .join(",");
    let mut command = std::process::Command::new("git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(certificate) = std::env::var_os("SSL_CERT_FILE") {
        command.env("GIT_SSL_CAINFO", certificate);
    }
    command.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "http.followRedirects=false",
        "-c",
        &format!("http.curloptResolve={host}:443:{resolve}"),
    ]);
    Ok(command)
}
