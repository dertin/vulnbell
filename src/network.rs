use crate::store::Store;
use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode, blocking::Client};
use rusqlite::params;
use serde::de::DeserializeOwned;
use std::{
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_BODY: u64 = 32 * 1024 * 1024;
const CACHE_TTL: u64 = 3600;
pub struct Http<'a> {
    pub store: &'a Store,
    pub offline: bool,
    pub requests: usize,
    pub cache_hits: usize,
    pub budget: usize,
    blocked_hosts: std::collections::HashSet<String>,
}
pub struct Response {
    pub body: Vec<u8>,
    pub url: String,
    pub truncated: bool,
}
impl Response {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..128).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| is_public(IpAddr::V4(ip)))
            .unwrap_or_else(|| {
                let segments = ip.segments();
                !ip.is_loopback()
                    && !ip.is_unspecified()
                    && (segments[0] & 0xe000 == 0x2000)
                    && !(segments[0] == 0x2001 && (segments[1] == 0xdb8 || segments[1] < 0x200))
            }),
    }
}
pub fn public_client(value: &str) -> Result<(Client, url::Url)> {
    let mut url = crate::profile::public_https_syntax(value)?;
    url.set_fragment(None);
    let host = url.host_str().context("missing host")?;
    let port = url.port_or_known_default().context("missing port")?;
    let addresses: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public(address.ip())) {
        bail!("SSRF protection: destination is not public");
    }
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(25))
        .user_agent(concat!("vulnbell/", env!("CARGO_PKG_VERSION")))
        .build()?;
    Ok((client, url))
}
impl<'a> Http<'a> {
    pub fn new(store: &'a Store, offline: bool) -> Self {
        Self {
            store,
            offline,
            requests: 0,
            cache_hits: 0,
            budget: 500,
            blocked_hosts: std::collections::HashSet::new(),
        }
    }
    pub fn get(&mut self, url: &str) -> Result<Response> {
        self.request(Method::GET, url, None)
    }
    pub fn post(&mut self, url: &str, body: &serde_json::Value) -> Result<Response> {
        self.request(Method::POST, url, Some(body))
    }
    fn request(
        &mut self,
        method: Method,
        value: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Response> {
        use rusqlite::OptionalExtension;
        let key = crate::digest(
            format!(
                "{method}:{value}:{}",
                body.map(serde_json::Value::to_string).unwrap_or_default()
            )
            .as_bytes(),
        );
        let cached: Option<(Vec<u8>, Option<String>, u64)> = self
            .store
            .connection
            .query_row(
                "SELECT body,etag,fetched_at FROM cache WHERE key=?1",
                [&key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if let Some((bytes, _, fetched_at)) = &cached
            && seconds.saturating_sub(*fetched_at) < CACHE_TTL
        {
            self.cache_hits += 1;
            return Ok(Response {
                body: bytes.clone(),
                url: value.into(),
                truncated: false,
            });
        }
        if self.offline {
            bail!("offline: fresh cached response unavailable");
        }
        if self.requests >= self.budget {
            bail!("HTTP request budget exhausted ({})", self.budget);
        }
        let (client, url) = public_client(value)?;
        let host = url.host_str().context("missing source host")?.to_owned();
        if self.blocked_hosts.contains(&host) {
            bail!("source limited: host budget exhausted in this scan");
        }
        for attempt in 0..3 {
            if self.requests >= self.budget {
                bail!("HTTP request budget exhausted");
            }
            self.requests += 1;
            let mut request = client
                .request(method.clone(), url.clone())
                .header("Accept", accept_for(&url));
            if url.host_str() == Some("api.github.com") {
                request = request.header("X-GitHub-Api-Version", "2022-11-28");
                if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                    request = request.bearer_auth(token);
                }
            }
            if url.host_str() == Some("gitlab.com")
                && let Ok(token) = std::env::var("GITLAB_TOKEN")
            {
                request = request.header("PRIVATE-TOKEN", token);
            }
            if url.host_str() == Some("services.nvd.nist.gov")
                && let Ok(token) = std::env::var("NVD_API_KEY")
            {
                request = request.header("apiKey", token);
            }
            if let Some(body) = body {
                request = request.json(body);
            }
            if let Some((_, Some(etag), _)) = &cached {
                request = request.header("If-None-Match", etag);
            }
            let response = request.send().map_err(|_| {
                anyhow::anyhow!(
                    "network request failed for {}",
                    url.host_str().unwrap_or("unknown")
                )
            })?;
            let status = response.status();
            if status == StatusCode::NOT_MODIFIED {
                let (bytes, _, _) = cached.as_ref().context("304 without cached body")?;
                self.store.connection.execute(
                    "UPDATE cache SET fetched_at=?1 WHERE key=?2",
                    params![seconds, key],
                )?;
                return Ok(Response {
                    body: bytes.clone(),
                    url: value.into(),
                    truncated: false,
                });
            }
            if status == StatusCode::FORBIDDEN
                && response
                    .headers()
                    .get("X-RateLimit-Remaining")
                    .is_some_and(|value| value == "0")
            {
                self.blocked_hosts.insert(host.clone());
                let reset = response
                    .headers()
                    .get("X-RateLimit-Reset")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<i64>().ok())
                    .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
                    .map(|time| time.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_owned());
                bail!("source limited: HTTP 403; provider rate budget exhausted; reset {reset}");
            }
            if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| {
                        value.parse::<u64>().ok().or_else(|| {
                            httpdate::parse_http_date(value).ok().map(|time| {
                                time.duration_since(SystemTime::now())
                                    .unwrap_or_default()
                                    .as_secs()
                            })
                        })
                    })
                    .unwrap_or(1 << attempt);
                if retry_after > 5 || attempt == 2 {
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        self.blocked_hosts.insert(host.clone());
                    }
                    bail!("source limited: HTTP {status}; Retry-After {retry_after}s");
                }
                std::thread::sleep(Duration::from_secs(retry_after));
                continue;
            }
            if !status.is_success() {
                bail!("source returned HTTP {status}");
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_BODY)
            {
                bail!("response exceeds 32 MiB limit");
            }
            let etag = response
                .headers()
                .get("ETag")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let truncated = response
                .headers()
                .get("Link")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("rel=\"next\""))
                || response
                    .headers()
                    .get("X-Next-Page")
                    .is_some_and(|value| !value.is_empty());
            let mut bytes = Vec::new();
            response.take(MAX_BODY + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_BODY {
                bail!("response exceeds 32 MiB limit");
            }
            // Paginated slices are never cached as complete responses.
            if !truncated {
                self.store.connection.execute(
                    "INSERT OR REPLACE INTO cache VALUES (?1,?2,?3,?4)",
                    params![key, bytes, etag, seconds],
                )?;
            }
            return Ok(Response {
                body: bytes,
                url: value.into(),
                truncated,
            });
        }
        bail!("retry budget exhausted")
    }
}

fn accept_for(url: &url::Url) -> &'static str {
    if url.host_str() == Some("github.com") {
        "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
    } else {
        "application/json"
    }
}

#[cfg(test)]
mod accept_tests {
    #[test]
    fn github_pages_and_api_use_appropriate_accept_headers() {
        let page = url::Url::parse(
            "https://github.com/example/project/security/advisories/GHSA-0000-0000-0000",
        )
        .unwrap();
        let api = url::Url::parse("https://api.github.com/advisories/GHSA-0000-0000-0000").unwrap();
        assert!(super::accept_for(&page).starts_with("text/html"));
        assert_eq!(super::accept_for(&api), "application/json");
    }
}
