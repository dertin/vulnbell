use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Read;

const MAX_MESSAGE: usize = 64 * 1024;
const MAX_BODY: u64 = 2 * 1024 * 1024;
const PAGE_SIZE: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    url: String,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    expected_sha256: Option<String>,
}

struct Document {
    requested_url: String,
    final_url: String,
    body: String,
    sha256: String,
}

#[derive(Default)]
struct WebSession {
    document: Option<Document>,
}

impl WebSession {
    fn fetch(&mut self, request: &FetchRequest) -> Result<Value> {
        if request.offset == 0 {
            self.document = Some(download(&request.url)?);
        }
        let document = self
            .document
            .as_ref()
            .context("fetch the first page before continuing")?;
        if document.requested_url != request.url {
            bail!("requested URL differs from the cached document");
        }
        page(document, request)
    }
}

fn page(document: &Document, request: &FetchRequest) -> Result<Value> {
    if request.offset > 0 && request.expected_sha256.as_deref() != Some(document.sha256.as_str()) {
        bail!("page changed or expected_sha256 is missing");
    }
    let body = &document.body;
    if request.offset > body.len() || !body.is_char_boundary(request.offset) {
        bail!("invalid offset");
    }
    let mut end = request.offset.saturating_add(PAGE_SIZE).min(body.len());
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    Ok(
        json!({"url":document.final_url,"sha256":document.sha256,"text":&body[request.offset..end],
        "next_offset":if end < body.len() { Some(end) } else { None }}),
    )
}

fn download(requested_url: &str) -> Result<Document> {
    if requested_url.len() > 2048 {
        bail!("URL exceeds limit");
    }
    let mut url = requested_url.to_owned();
    for _ in 0..=3 {
        let (client, target) = vulnbell::network::public_client(&url)?;
        let response = client
            .get(target.clone())
            .header(
                "Accept",
                "text/html,text/plain,application/json,application/xml;q=0.9",
            )
            .send()
            .context("public web request failed")?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("redirect has no location")?
                .to_str()?;
            url = target.join(location)?.to_string();
            continue;
        }
        if !response.status().is_success() {
            bail!("public web source returned HTTP {}", response.status());
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_BODY)
        {
            bail!("public web response exceeds limit");
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !content_type.is_empty()
            && !content_type.starts_with("text/")
            && !matches!(
                content_type.as_str(),
                "application/json" | "application/xml" | "application/xhtml+xml"
            )
        {
            bail!("public web response is not text");
        }
        let mut body = Vec::new();
        response.take(MAX_BODY + 1).read_to_end(&mut body)?;
        if body.len() as u64 > MAX_BODY {
            bail!("public web response exceeds limit");
        }
        let body = String::from_utf8(body).context("public web response is not UTF-8")?;
        return Ok(Document {
            requested_url: requested_url.to_owned(),
            final_url: target.to_string(),
            sha256: vulnbell::digest(body.as_bytes()),
            body,
        });
    }
    bail!("too many public web redirects")
}

pub(super) fn serve() -> Result<()> {
    let mut session = WebSession::default();
    let tools = json!([{"name":"public_fetch","description":"Read a public HTTPS page as untrusted text. To continue, pass next_offset and expected_sha256 from the preceding response.","annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":true},"inputSchema":{"type":"object","properties":{"url":{"type":"string"},"offset":{"type":"integer","minimum":0},"expected_sha256":{"type":"string"}},"required":["url"],"additionalProperties":false}}]);
    vulnbell::runners::serve_mcp("vulnbell-web", MAX_MESSAGE, tools, |name, arguments| {
        if name != "public_fetch" {
            bail!("unknown tool");
        }
        session.fetch(&serde_json::from_value(arguments)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_public_or_authenticated_destinations() {
        for url in [
            "http://example.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://user:password@example.com",
        ] {
            let request = FetchRequest {
                url: url.into(),
                offset: 0,
                expected_sha256: None,
            };
            assert!(WebSession::default().fetch(&request).is_err(), "{url}");
        }
    }

    #[test]
    fn pagination_preserves_utf8_and_requires_the_same_content() {
        let body = "á".repeat(PAGE_SIZE);
        let mut request = FetchRequest {
            url: "https://example.com".into(),
            offset: 0,
            expected_sha256: None,
        };
        let document = Document {
            requested_url: request.url.clone(),
            final_url: request.url.clone(),
            sha256: vulnbell::digest(body.as_bytes()),
            body: body.clone(),
        };
        let mut session = WebSession {
            document: Some(document),
        };
        let first = page(session.document.as_ref().unwrap(), &request).unwrap();
        request.offset = first["next_offset"].as_u64().unwrap() as usize;
        assert!(session.fetch(&request).is_err());
        request.expected_sha256 = Some(first["sha256"].as_str().unwrap().into());
        let second = session.fetch(&request).unwrap();
        assert_eq!(
            format!(
                "{}{}",
                first["text"].as_str().unwrap(),
                second["text"].as_str().unwrap()
            ),
            body
        );
        request.url = "https://different.example".into();
        assert!(session.fetch(&request).is_err());
    }
}
