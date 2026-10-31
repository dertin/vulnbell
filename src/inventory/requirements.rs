use crate::model::{Instance, Origin, Provenance};
use anyhow::Result;
use pep508_rs::{Requirement, VerbatimUrl, VersionOrUrl, pep440_rs::Operator};
use std::{collections::BTreeMap, str::FromStr};

fn nesting_within_limit(line: &str) -> bool {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for byte in line.bytes() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
        } else {
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => {
                    depth += 1;
                    if depth > 32 {
                        return false;
                    }
                }
                b')' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    true
}

pub(super) fn parse(
    bytes: &[u8],
    workspace: &str,
    path: &str,
    budget: usize,
) -> Result<(Vec<Instance>, String)> {
    let text = std::str::from_utf8(bytes)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let hash = crate::digest(bytes);
    let mut lines = Vec::new();
    let mut logical = String::new();
    let mut start = 0;
    let mut line_limit = false;
    for (index, line) in text.lines().enumerate() {
        if lines.len() >= 100_000 {
            line_limit = true;
            break;
        }
        if logical.is_empty() {
            start = index + 1;
        }
        let line = line.trim_end();
        let continued = line.ends_with('\\');
        logical.push_str(if continued {
            &line[..line.len() - 1]
        } else {
            line
        });
        if !continued {
            lines.push((start, std::mem::take(&mut logical)));
        }
    }
    let incomplete_line = !logical.is_empty();
    let uncertain_source = line_limit
        || incomplete_line
        || lines.iter().any(|(_, line)| {
            let line = line.trim_start();
            [
                "--index-url",
                "--extra-index-url",
                "--no-index",
                "--find-links",
                "--requirement",
                "--constraint",
                "-i",
                "-f",
                "-r",
                "-c",
            ]
            .iter()
            .any(|option| line.starts_with(option))
        });
    let mut unsupported = usize::from(incomplete_line);
    let mut unsupported_lines = Vec::new();
    if incomplete_line {
        unsupported_lines.push(start);
    }
    let mut unresolved = 0usize;
    let mut conditional = 0usize;
    let mut truncated = false;
    let mut instances = Vec::new();
    let mut occurrences: BTreeMap<(String, Option<String>), usize> = BTreeMap::new();
    for (line_number, line) in lines {
        let comment = line.char_indices().find_map(|(index, character)| {
            (character == '#' && (index == 0 || line.as_bytes()[index - 1].is_ascii_whitespace()))
                .then_some(index)
        });
        let line = line[..comment.unwrap_or(line.len())].trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > 16 * 1024
            || !nesting_within_limit(line)
            || line.starts_with('-')
            || line.contains("${")
        {
            unsupported += 1;
            if unsupported_lines.len() < 16 {
                unsupported_lines.push(line_number);
            }
            continue;
        }
        let mut words = line.split_whitespace();
        let mut requirement = Vec::new();
        let mut invalid_option = false;
        while let Some(word) = words.next() {
            if word == "--hash" {
                invalid_option |= words.next().is_none();
            } else if word.starts_with("--hash=") {
                invalid_option |= word.len() == "--hash=".len();
            } else if word.starts_with('-') {
                invalid_option = true;
            } else {
                requirement.push(word);
            }
        }
        if invalid_option {
            unsupported += 1;
            if unsupported_lines.len() < 16 {
                unsupported_lines.push(line_number);
            }
            continue;
        }
        let Ok(requirement) = Requirement::<VerbatimUrl>::from_str(&requirement.join(" ")) else {
            unsupported += 1;
            if unsupported_lines.len() < 16 {
                unsupported_lines.push(line_number);
            }
            continue;
        };
        if matches!(requirement.version_or_url, Some(VersionOrUrl::Url(_))) {
            unsupported += 1;
            if unsupported_lines.len() < 16 {
                unsupported_lines.push(line_number);
            }
            continue;
        }
        let specifier = match &requirement.version_or_url {
            Some(VersionOrUrl::VersionSpecifier(specifiers)) => Some(
                specifiers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            _ => None,
        };
        let version = match &requirement.version_or_url {
            Some(VersionOrUrl::VersionSpecifier(specifiers)) => {
                let pins: Vec<_> = specifiers
                    .iter()
                    .filter(|specifier| *specifier.operator() == Operator::Equal)
                    .collect();
                match pins.as_slice() {
                    [pin] if specifiers.contains(pin.version()) => Some(pin.version().to_string()),
                    _ => None,
                }
            }
            _ => None,
        };
        let requested = version.clone().or(specifier);
        if version.is_none() {
            unresolved += 1;
        }
        if !requirement.marker.is_true() {
            conditional += 1;
        }
        if instances.len() >= budget {
            truncated = true;
            break;
        }
        let name = requirement.name.to_string();
        let purl = if uncertain_source {
            None
        } else {
            Some(packageurl::PackageUrl::new("pypi", &name)?.to_string())
        };
        let reference = purl
            .clone()
            .unwrap_or_else(|| format!("python-requirement:{name}"));
        let occurrence = occurrences
            .entry((reference.clone(), requested.clone()))
            .or_default();
        let id = crate::digest(
            format!("requirement:{workspace:?}:{path:?}:{reference:?}:{requested:?}:{occurrence}")
                .as_bytes(),
        );
        *occurrence += 1;
        instances.push(Instance {
            id,
            reference,
            requested_version: requested,
            resolved_version: version,
            origin: Origin::Declared,
            provenance: Provenance {
                path: Some(path.to_owned()),
                sha256: hash.clone(),
                observed_at: crate::now(),
                workspace: Some(workspace.to_owned()),
                workspace_context_sha256: None,
                direct: None,
                resolution: (!requirement.marker.is_true())
                    .then(|| "environment marker not evaluated".into()),
                artifact_integrity: None,
                line: Some(line_number),
            },
            purl,
            cpe_product: None,
            upstream: None,
            identity_evidence: Vec::new(),
            release: None,
        });
    }
    let unsupported_locations = if unsupported_lines.is_empty() {
        String::new()
    } else {
        format!(
            " (first lines: {})",
            unsupported_lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let detail = format!(
        "requirements declarations are not installed inventory; directness, source and dependency closure are unverified; {unresolved} unpinned, {conditional} conditional and {unsupported} unsupported entries{unsupported_locations}; {}; {}",
        if uncertain_source {
            "public package identities not inferred due to index or included-file options"
        } else {
            "public package identities require source confirmation"
        },
        if line_limit {
            "100000 line limit reached"
        } else if truncated {
            "instance budget exhausted"
        } else {
            "includes, constraints and private indexes require review"
        }
    );
    Ok((instances, detail))
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn keeps_pins_ranges_markers_and_hashes_without_executing_input() {
        let text = b"# sample\nRequests[security]==2.31.0 \\\n    --hash=sha256:abc\nurllib3>=1.26,<3\nwinpkg==1.2; sys_platform == 'win32'\nprivate @ https://user:secret@example.invalid/pkg.whl\n";
        let (items, detail) = parse(text, "workspace", "requirements.txt", 10).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].reference, "pkg:pypi/requests");
        assert_eq!(items[0].resolved_version.as_deref(), Some("2.31.0"));
        assert_eq!(items[0].provenance.line, Some(2));
        assert_eq!(items[0].provenance.direct, None);
        assert_eq!(items[1].resolved_version, None);
        assert!(
            items[1]
                .requested_version
                .as_deref()
                .unwrap()
                .contains(">=1.26")
        );
        assert_eq!(
            items[2].provenance.resolution.as_deref(),
            Some("environment marker not evaluated")
        );
        assert!(detail.contains("1 unpinned, 1 conditional and 1 unsupported"));
        assert!(!format!("{items:?}{detail}").contains("secret"));
    }

    #[test]
    fn private_indexes_and_included_files_do_not_infer_public_identity() {
        for directive in [
            "--index-url https://user:secret@example.invalid/simple",
            "-r other.txt",
            "-c constraints.txt",
        ] {
            let text = format!("requests==2.31.0\n{directive}\n");
            let (items, detail) =
                parse(text.as_bytes(), "workspace", "requirements.txt", 10).unwrap();
            assert_eq!(items[0].reference, "python-requirement:requests");
            assert_eq!(items[0].purl, None);
            assert!(detail.contains("public package identities not inferred"));
            assert!(!format!("{items:?}{detail}").contains("secret"));
        }
    }

    #[test]
    fn wildcard_conflicting_and_budgeted_requirements_stay_unresolved() {
        let text = b"a==1.*\nb==1.0,!=1.0\nc==2.0\n";
        let (items, detail) = parse(text, "workspace", "requirements.txt", 2).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| item.resolved_version.is_none()));
        assert!(detail.contains("instance budget exhausted"));
    }

    #[test]
    fn excessive_marker_nesting_is_left_for_review() {
        let text = format!(
            "requests==2.31.0; {}python_version > '3'{}\n",
            "(".repeat(100),
            ")".repeat(100)
        );
        let (items, detail) = parse(text.as_bytes(), "workspace", "requirements.txt", 10).unwrap();
        assert!(items.is_empty());
        assert!(detail.contains("1 unsupported"));
    }

    #[test]
    fn utf8_bom_does_not_hide_the_first_requirement() {
        let (items, _) = parse(
            "\u{feff}requests==2.31.0\n".as_bytes(),
            "workspace",
            "requirements.txt",
            10,
        )
        .unwrap();
        assert_eq!(items[0].reference, "pkg:pypi/requests");
        assert_eq!(items[0].provenance.line, Some(1));
    }
}
