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

mod pagination;

const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
const MAX_PDF: u64 = 64 * 1024 * 1024;

fn text(value: &str) -> String {
    super::markdown::inline(value)
}

fn evidence_link(value: &str) -> String {
    match url::Url::parse(value) {
        Ok(url)
            if url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none() =>
        {
            format!("<{}>", url.as_str())
        }
        _ => text(value),
    }
}

fn attestation_details(attestation: &crate::sandbox::Attestation, language: Language) -> String {
    let (oracle, control, execution, inputs, expected, marker, complete, exit) = match language {
        Language::Es => (
            "Oráculo",
            "Control",
            "Ejecución",
            "Hashes de entrada",
            "salida esperada",
            "marcador",
            "completo",
            "salida",
        ),
        Language::En => (
            "Oracle",
            "Control",
            "Execution",
            "Input hashes",
            "expected exit",
            "marker",
            "complete",
            "exit",
        ),
    };
    let mut out = format!(
        "  - {oracle}: {:?}; {expected} `{}`; {marker} `{}`.\n  - {execution}: {complete}={}; timeout={}; {exit}={:?}; SHA-256 `{}`.\n  - {inputs}: {}.\n",
        attestation.oracle.purpose,
        attestation.oracle.expected_exit,
        text(&attestation.oracle.stdout_contains),
        attestation.execution_complete,
        attestation.timed_out,
        attestation.exit_code,
        text(&attestation.output_sha256),
        text(&attestation.input_sha256.join(", ")),
    );
    if let Some(observation) = &attestation.control {
        let (input, output) = match language {
            Language::Es => ("entrada", "salida"),
            Language::En => ("input", "output"),
        };
        out.push_str(&format!(
            "  - {control}: {}; oracle_matched={}; policy_verified={}; {input} SHA-256 {}; {output} SHA-256 `{}`.\n",
            text(&observation.artifact_version),
            observation.oracle_matched,
            observation.policy_verified,
            text(&observation.input_sha256.join(", ")),
            text(&observation.output_sha256),
        ));
    } else {
        out.push_str(match language {
            Language::Es => "  - Control: no registrado.\n",
            Language::En => "  - Control: not recorded.\n",
        });
    }
    out
}

/// Include all recorded verification details without repeating the standard section.
pub fn report_body(markdown: &str, report: &super::MorningReport) -> Result<String> {
    let markdown = super::normalize_report_paths(report, markdown)?;
    let body = super::branding::without_footer(&markdown);
    let markdown = if body.len() == markdown.len() {
        markdown
    } else {
        format!("{body}\n\n")
    };
    if report.finding_checks.is_empty() {
        return Ok(markdown);
    }
    let compact = super::normalize_report_paths(
        report,
        &super::markdown::verification_section(report, false),
    )?;
    let needs_review: std::collections::HashSet<&str> = report
        .needs_review
        .iter()
        .map(|item| item.case_id.as_str())
        .collect();
    let checks: Vec<&super::verification::FindingCheck> = report
        .finding_checks
        .iter()
        .filter(|check| check.decision != crate::model::Decision::Retracted)
        .filter(|check| {
            matches!(
                check.decision,
                crate::model::Decision::Actionable | crate::model::Decision::Review
            ) || needs_review.contains(check.case_id.as_str())
        })
        .collect();
    let full = super::normalize_report_paths(
        report,
        &super::verification::markdown(&checks, true, report.language),
    )?;
    if markdown.contains(&full) {
        Ok(markdown)
    } else if !compact.is_empty() && markdown.contains(&compact) {
        Ok(markdown.replacen(&compact, &full, 1))
    } else {
        let (original, current) = match report.language {
            Language::Es => (
                "## Referencias y verificación local",
                "## Verificación registrada por VulnBell",
            ),
            Language::En => (
                "## References and local verification",
                "## Verification recorded by VulnBell",
            ),
        };
        let full = if markdown.contains(original) {
            full.replacen(original, current, 1)
        } else {
            full
        };
        Ok(format!("{markdown}\n\n{full}"))
    }
}

/// Extend the report with evidence metadata and locally registered review notes.
fn pdf_markdown(
    markdown: &str,
    cases: &[&Case],
    store: &Store,
    language: Language,
) -> Result<String> {
    let mut output = markdown.to_owned();
    output.push_str(match language {
        Language::Es => "\n\n# Anexo de evidencias\n\nLas notas registradas y las salidas de sandbox en texto se incluyen a continuación. Las rutas de codebases conocidas se muestran de forma relativa; los hashes corresponden al contenido original registrado. Los documentos originales, archivos binarios y respuestas completas de fuentes externas no se incluyen; sus identificadores, enlaces y hashes permiten localizarlos.\n\n",
        Language::En => "\n\n# Evidence appendix\n\nRegistered review notes and textual sandbox output are included below. Known codebase paths are shown relative to the codebase; hashes identify the original recorded content. Original documents, binary files, and full external responses are not included; their identifiers, links, and hashes identify them.\n\n",
    });
    let mut ordered: Vec<&Case> = cases.to_vec();
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
                    "- {}: {} - {}\n",
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
                "- {}: {} {} - SHA-256 `{}`\n",
                text(&event.kind),
                text(&event.title),
                evidence_link(&event.url),
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
                "- {} - {} - SHA-256 `{}` - {} - {}",
                text(&evidence.id),
                text(&evidence.source),
                text(&evidence.sha256),
                text(&evidence.observed_at),
                state
            ));
            if let Some(url) = &evidence.url {
                output.push_str(&format!(" - {}", evidence_link(url)));
            }
            output.push('\n');
            if evidence.kind == crate::model::EvidenceKind::Attestation {
                match crate::sandbox::read_attestation(case, store, evidence) {
                    Ok(attestation) => {
                        output.push_str(&attestation_details(&attestation, language))
                    }
                    Err(_) => output.push_str(match language {
                        Language::Es => "  - Atestación no disponible o inválida.\n",
                        Language::En => "  - Attestation unavailable or invalid.\n",
                    }),
                }
            }
            if valid
                && matches!(
                    evidence.source.as_str(),
                    "local_impact_evidence"
                        | "local_scope_evidence"
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
    let output = super::branding::finish(&output, language);
    if output.len() > MAX_DOCUMENT {
        bail!("report and evidence appendix exceed the 16 MiB PDF input limit");
    }
    Ok(output)
}

/// Build the appendix and normalize registered codebase paths before PDF export.
pub fn prepared_pdf_markdown(
    markdown: &str,
    cases: &[Case],
    store: &Store,
    report: &super::MorningReport,
) -> Result<String> {
    let markdown = super::normalize_report_paths(report, markdown)?;
    let markdown = super::branding::custom(&markdown, report.language)?;
    let markdown = super::branding::without_footer(&markdown);
    super::ensure_morning_report_store(report, store)?;
    let roots: std::collections::HashSet<&str> = report
        .codebase_path_roots
        .iter()
        .map(String::as_str)
        .collect();
    if cases.iter().any(|case| {
        case.project_id != report.project_id
            || case
                .codebase_revisions
                .iter()
                .any(|revision| !roots.contains(revision.codebase.as_str()))
    }) {
        bail!("PDF cases do not match the prepared report context");
    }
    let needs_review: std::collections::HashSet<&str> = report
        .needs_review
        .iter()
        .map(|item| item.case_id.as_str())
        .collect();
    let selected: Vec<&Case> = cases
        .iter()
        .filter(|case| case.decision != crate::model::Decision::Retracted)
        .filter(|case| {
            report.closed == super::ClosedMode::Full
                || matches!(
                    case.decision,
                    crate::model::Decision::Actionable | crate::model::Decision::Review
                )
                || needs_review.contains(case.case_id.as_str())
        })
        .collect();
    let document = pdf_markdown(markdown, &selected, store, report.language)?;
    super::normalize_report_paths(report, &document)
}

fn safe_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options
        .insert(Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS);
    let oversized = pagination::oversized_lists(markdown, options);
    let mut links = Vec::new();
    let events = Parser::new_ext(markdown, options).map(|event| match event {
        Event::Html(value) | Event::InlineHtml(value) | Event::Text(value) => {
            Event::Text(value.replace('—', "-").into())
        }
        Event::Code(value) => Event::Code(value.replace('—', "-").into()),
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
    html::push_html(&mut body, pagination::wrap_oversized(events, oversized));
    let appendix = ["Anexo de evidencias", "Evidence appendix"]
        .into_iter()
        .filter_map(|heading| {
            let marker = format!("<h1>{heading}</h1>");
            body.rfind(&marker).map(|start| (start, marker, heading))
        })
        .max_by_key(|(start, _, _)| *start);
    if let Some((start, marker, heading)) = appendix {
        body.replace_range(
            start..start + marker.len(),
            &format!("<h1 class=\"evidence-appendix\">{heading}</h1>"),
        );
    }
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"><title>VulnBell report</title><style>{}</style></head><body>{body}</body></html>"#,
        include_str!("pdf.css"),
    )
}

pub(crate) fn browser_path(explicit: Option<&Path>) -> Result<PathBuf> {
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
mod tests;
