use crate::{model::Case, profile::Language, store::Store};
use anyhow::{Context, Result, bail};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd, html};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
const MAX_PDF: u64 = 64 * 1024 * 1024;

fn text(value: &str) -> String {
    super::markdown::inline(value)
}

/// Extend the report with evidence metadata and locally registered review notes.
pub fn pdf_markdown(
    markdown: &str,
    cases: &[Case],
    store: &Store,
    language: Language,
) -> Result<String> {
    let mut output = markdown.to_owned();
    output.push_str(match language {
        Language::Es => "\n\n# Anexo de evidencias\n\nLas notas registradas y las salidas de sandbox en texto se incluyen a continuación. Los documentos originales, archivos binarios y respuestas completas de fuentes externas no se incluyen; sus identificadores, enlaces y hashes permiten localizarlos.\n\n",
        Language::En => "\n\n# Evidence appendix\n\nRegistered review notes and textual sandbox output are included below. Original documents, binary files, and full external responses are not included; their identifiers, links, and hashes identify them.\n\n",
    });
    let mut ordered: Vec<&Case> = cases.iter().collect();
    ordered.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    for case in ordered {
        output.push_str(&format!("## {}\n\n", text(&case.case_id)));
        output.push_str(&format!(
            "- {}: {} · {} · {}\n",
            match language {
                Language::Es => "Estado",
                Language::En => "Status",
            },
            super::text::decision(language, case.decision),
            super::text::applicability(language, case.applicability),
            super::text::verification(language, case.verification),
        ));
        if let Some(verdict) = crate::engine::current_verdict(case, store) {
            output.push_str(&format!(
                "- {}: {}\n",
                match language {
                    Language::Es => "Justificación del veredicto",
                    Language::En => "Verdict rationale",
                },
                text(&verdict.rationale)
            ));
        }
        if let Some(impact) = crate::impact::latest(case, store) {
            for answer in &impact.answers {
                output.push_str(&format!(
                    "- {}: {} — {}\n",
                    super::text::impact_question(language, answer.question),
                    super::text::impact_answer(language, answer.answer),
                    text(&answer.rationale),
                ));
            }
        }
        for question in &case.open_questions {
            output.push_str(&format!(
                "- {}: {}\n",
                match language {
                    Language::Es => "Pendiente",
                    Language::En => "Open question",
                },
                text(question)
            ));
        }
        for instance in &case.instances {
            output.push_str(&format!(
                "- {}: {} {}\n",
                match language {
                    Language::Es => "Componente",
                    Language::En => "Component",
                },
                text(&instance.reference),
                text(instance.resolved_version.as_deref().unwrap_or("?"))
            ));
        }
        for claim in &case.claims {
            output.push_str(&format!(
                "- {} {}: {}\n",
                text(&claim.source),
                text(&claim.id),
                text(&claim.summary)
            ));
        }
        for event in &case.upstream_events {
            output.push_str(&format!(
                "- {}: {} <{}> — SHA-256 `{}`\n",
                text(&event.kind),
                text(&event.title),
                text(&event.url),
                text(&event.sha256)
            ));
            if !event.source_facts.identifiers.is_empty() {
                output.push_str(&format!(
                    "  - {}: {}\n",
                    match language {
                        Language::Es => "Identificadores",
                        Language::En => "Identifiers",
                    },
                    text(&event.source_facts.identifiers.join(", "))
                ));
            }
            for (label, value) in [
                (
                    match language {
                        Language::Es => "Versiones afectadas",
                        Language::En => "Affected versions",
                    },
                    event.source_facts.affected_versions.as_str(),
                ),
                (
                    match language {
                        Language::Es => "Corrección",
                        Language::En => "Fix",
                    },
                    event.source_facts.fixed_in.as_str(),
                ),
                (
                    match language {
                        Language::Es => "Referencia de corrección",
                        Language::En => "Fix reference",
                    },
                    event.source_facts.fix_reference.as_str(),
                ),
                (
                    match language {
                        Language::Es => "Función requerida",
                        Language::En => "Required feature",
                    },
                    event.source_facts.required_feature.as_str(),
                ),
            ] {
                if !value.is_empty() {
                    output.push_str(&format!("  - {label}: {}\n", text(value)));
                }
            }
        }
        let mut seen = BTreeSet::new();
        for evidence in &case.evidence {
            if !seen.insert((&evidence.sha256, &evidence.source)) {
                continue;
            }
            let hash_valid = evidence.sha256.len() == 64
                && evidence
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
            let contents = hash_valid
                .then(|| {
                    crate::read_limited(
                        &store.directory.join("evidence").join(&evidence.sha256),
                        32 * 1024 * 1024,
                    )
                    .ok()
                })
                .flatten()
                .filter(|bytes| crate::digest(bytes) == evidence.sha256);
            let valid = contents.is_some();
            let state = match (language, valid) {
                (Language::Es, true) => "integridad verificada",
                (Language::Es, false) => "no disponible o integridad inválida",
                (Language::En, true) => "integrity verified",
                (Language::En, false) => "unavailable or invalid integrity",
            };
            output.push_str(&format!(
                "- {} — {} — SHA-256 `{}` — {} — {}",
                text(&evidence.id),
                text(&evidence.source),
                text(&evidence.sha256),
                text(&evidence.observed_at),
                state
            ));
            if let Some(url) = &evidence.url {
                output.push_str(&format!(" — <{}>", text(url)));
            }
            output.push('\n');
            if valid
                && matches!(
                    evidence.source.as_str(),
                    "local_impact_evidence"
                        | "review_handoff_note"
                        | "agent_note"
                        | "microsandbox_stdout"
                        | "microsandbox_stderr"
                        | "microsandbox_control_output"
                )
            {
                match contents
                    .filter(|bytes| bytes.len() <= 1024 * 1024)
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                {
                    Some(note) => {
                        output.push('\n');
                        for line in note.lines() {
                            output.push_str("    ");
                            output.push_str(line);
                            output.push('\n');
                        }
                        output.push('\n');
                    }
                    None => output.push_str(match language {
                        Language::Es => "  - Nota no disponible como texto UTF-8 de hasta 1 MiB.\n",
                        Language::En => "  - Note unavailable as UTF-8 text up to 1 MiB.\n",
                    }),
                }
            }
            if output.len() > MAX_DOCUMENT {
                bail!("report and evidence appendix exceed the 16 MiB PDF input limit");
            }
        }
        output.push('\n');
        if output.len() > MAX_DOCUMENT {
            bail!("report and evidence appendix exceed the 16 MiB PDF input limit");
        }
    }
    if output.len() > MAX_DOCUMENT {
        bail!("report and evidence appendix exceed the 16 MiB PDF input limit");
    }
    Ok(output)
}

fn safe_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options
        .insert(Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS);
    let mut links = Vec::new();
    let events = Parser::new_ext(markdown, options).map(|event| match event {
        Event::Html(value) | Event::InlineHtml(value) => Event::Text(value),
        Event::Start(Tag::Image { .. }) | Event::End(TagEnd::Image) => Event::Text("".into()),
        Event::Start(tag @ Tag::Link { .. }) => {
            let safe = if let Tag::Link { dest_url, .. } = &tag {
                url::Url::parse(dest_url).is_ok_and(|url| {
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                })
            } else {
                false
            };
            links.push(safe);
            if safe {
                Event::Start(tag)
            } else {
                Event::Text("".into())
            }
        }
        Event::End(TagEnd::Link) if !links.pop().unwrap_or(false) => Event::Text("".into()),
        other => other,
    });
    let mut body = String::new();
    html::push_html(&mut body, events);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\"><title>VulnBell report</title><style>@page{{size:A4;margin:18mm 15mm;@bottom-right{{content:counter(page) \" / \" counter(pages);font:8pt sans-serif;color:#52647a}}}}body{{font:10pt/1.45 sans-serif;color:#182338}}h1,h2,h3{{color:#183a67;break-after:avoid}}h1{{font-size:20pt}}h2{{font-size:15pt;border-bottom:1px solid #cad5e3;padding-bottom:4px}}h3{{font-size:12pt}}p,li{{overflow-wrap:anywhere}}table{{width:100%;border-collapse:collapse;font-size:8.5pt;table-layout:fixed}}th,td{{border:1px solid #cad5e3;padding:5px;vertical-align:top;overflow-wrap:anywhere}}th{{background:#eaf0f7;text-align:left}}tr{{break-inside:avoid}}thead{{display:table-header-group}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:8px;font-size:8pt}}code{{overflow-wrap:anywhere}}a{{color:#1554a0;overflow-wrap:anywhere}}blockquote{{border-left:3px solid #b86b10;margin-left:0;padding-left:10px}}</style></head><body>{body}</body></html>"
    )
}

fn browser_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let names: &[&str] = if cfg!(windows) {
        &["chrome.exe", "msedge.exe", "chromium.exe"]
    } else {
        &[
            "google-chrome",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
        ]
    };
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for name in names {
            let path = directory.join(name);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    #[cfg(target_os = "macos")]
    for path in [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ] {
        if Path::new(path).is_file() {
            return Ok(PathBuf::from(path));
        }
    }
    #[cfg(target_os = "windows")]
    for variable in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(variable) {
            for executable in [
                "Google/Chrome/Application/chrome.exe",
                "Microsoft/Edge/Application/msedge.exe",
                "Chromium/Application/chrome.exe",
            ] {
                let path = PathBuf::from(&root).join(executable);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }
    bail!("Chromium-based browser not found; specify --pdf-browser")
}

/// Render Markdown through an isolated browser profile without scripts or external resources.
pub fn write_pdf(markdown: &str, output: &Path, browser: Option<&Path>) -> Result<()> {
    if markdown.len() > MAX_DOCUMENT {
        bail!("PDF input exceeds 16 MiB");
    }
    match fs::symlink_metadata(output) {
        Ok(_) => bail!("PDF destination already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error).context("cannot inspect PDF destination"),
    }
    let renderer = browser_path(browser)?;
    let temp = tempfile::tempdir().context("cannot create private PDF workspace")?;
    let input = temp.path().join("report.html");
    let result = temp.path().join("report.pdf");
    fs::write(&input, safe_html(markdown))?;
    let url = url::Url::from_file_path(&input)
        .map_err(|_| anyhow::anyhow!("invalid PDF workspace path"))?;
    let mut command = Command::new(renderer);
    command.env_clear();
    for key in ["PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("HOME", temp.path())
        .env("USERPROFILE", temp.path())
        .env("TMP", temp.path())
        .env("TEMP", temp.path());
    command.args([
        "--headless",
        "--disable-gpu",
        "--disable-javascript",
        "--disable-extensions",
        "--disable-background-networking",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-pdf-header-footer",
        "--host-resolver-rules=MAP * ~NOTFOUND",
    ]);
    command.arg(format!(
        "--user-data-dir={}",
        temp.path().join("profile").display()
    ));
    command.arg(format!("--print-to-pdf={}", result.display()));
    command.arg(url.as_str());
    let process = crate::process::run_renderer(&mut command, 120, 1024 * 1024)?;
    if !process.success {
        bail!(
            "PDF browser failed or timed out (exit {:?}, timed_out {})",
            process.exit_code,
            process.timed_out
        );
    }
    let bytes = crate::read_limited(&result, MAX_PDF)
        .context("PDF browser did not produce a readable file")?;
    if !bytes.starts_with(b"%PDF-") {
        bail!("PDF browser returned an invalid file");
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file =
        tempfile::NamedTempFile::new_in(parent).context("cannot create PDF in destination")?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(output)
        .map_err(|error| error.error)
        .context("cannot write PDF; destination must not already exist")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{pdf_markdown, safe_html, write_pdf};
    #[test]
    fn report_html_disables_active_content_and_external_images() {
        let output = safe_html(
            "# Test\n\n<script>alert(1)</script>\n\n![image](https://example.com/x.png) [bad](javascript:alert) [good](https://example.com/advisory)",
        );
        assert!(!output.contains("<script>"));
        assert!(!output.contains("<img"));
        assert!(!output.contains("href=\"javascript:"));
        assert!(output.contains("href=\"https://example.com/advisory\""));
        assert!(output.contains("default-src 'none'"));
    }

    #[test]
    fn appendix_contains_registered_notes_and_reports_missing_evidence() {
        use crate::model::{
            Applicability, Case, Decision, EvidenceKind, SandboxAvailability, Verification,
        };
        let project = uuid::Uuid::new_v4().to_string();
        let store = crate::store::Store::open(&project).unwrap();
        let note = store
            .record_evidence(
                b"Reachable at src/auth.rs:12",
                "local_impact_evidence",
                None,
                EvidenceKind::Context,
            )
            .unwrap();
        let mut missing = note.clone();
        missing.id = "EV-missing".into();
        missing.sha256 = "../outside".into();
        let case = Case {
            schema_version: 1,
            case_id: "SIG-test".into(),
            project_id: project.clone(),
            snapshot_id: "snapshot".into(),
            workspace_revisions: vec![],
            instances: vec![],
            claims: vec![],
            upstream_events: vec![],
            evidence: vec![note.clone(), missing],
            coverage: vec![],
            applicability: Applicability::Unknown,
            verification: Verification::Inconclusive,
            decision: Decision::Review,
            facts_sha256: "facts".into(),
            open_questions: vec![],
            suggested_search_queries: vec![],
            sandbox: SandboxAvailability {
                available: false,
                reason: "not run".into(),
            },
            updated_at: "now".into(),
        };
        let output =
            pdf_markdown("# Report", &[case], &store, crate::profile::Language::Es).unwrap();
        assert!(output.contains("SIG-test"));
        assert!(output.contains("Reachable at src/auth.rs:12"));
        assert!(output.contains(&note.sha256));
        assert!(output.contains("no disponible o integridad inválida"));
        assert!(
            pdf_markdown(
                &"a".repeat(super::MAX_DOCUMENT + 1),
                &[],
                &store,
                crate::profile::Language::En
            )
            .is_err()
        );
        drop(store);
        std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    }

    #[test]
    fn existing_pdf_is_not_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.pdf");
        std::fs::write(&path, b"existing").unwrap();
        assert!(
            write_pdf(
                "# Report",
                &path,
                Some(std::path::Path::new("missing-browser"))
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"existing");
    }
}
