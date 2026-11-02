use crate::model::{Instance, Origin, Provenance, PythonLock};
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

fn via_annotations(text: &str) -> BTreeMap<usize, Vec<String>> {
    let mut result: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut entry = None;
    let mut continuing = false;
    let mut collecting = false;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(comment) = trimmed.strip_prefix('#') {
            let comment = comment.trim();
            if comment == "via" {
                collecting = true;
            } else if let Some(value) = comment.strip_prefix("via ") {
                if let Some(entry) = entry {
                    result
                        .entry(entry)
                        .or_default()
                        .push(value.trim().to_owned());
                }
                collecting = false;
            } else if collecting && let Some(entry) = entry {
                result.entry(entry).or_default().push(comment.to_owned());
            }
            continue;
        }
        if trimmed.is_empty() {
            collecting = false;
            continue;
        }
        if !continuing {
            entry = (!trimmed.starts_with('-')).then_some(index + 1);
        }
        continuing = trimmed.ends_with('\\');
        collecting = false;
    }
    result
}

fn safe_via(value: &str) -> Option<String> {
    if let Some(path) = value.strip_prefix("-r ") {
        let path = std::path::Path::new(path.trim());
        if !path.as_os_str().is_empty()
            && path
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            return path.to_str().map(|path| format!("-r {path}"));
        }
        return None;
    }
    let name = value.split('[').next()?.trim();
    if !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        Some(crate::identity::normalize_pypi(name))
    } else {
        None
    }
}

fn matches_declared_version(requested: Option<&str>, resolved: &str) -> bool {
    let Ok(version) = resolved.parse::<pep508_rs::pep440_rs::Version>() else {
        return false;
    };
    let Some(requested) = requested else {
        return true;
    };
    if let Ok(exact) = requested.parse::<pep508_rs::pep440_rs::Version>() {
        return exact == version;
    }
    requested
        .parse::<pep508_rs::pep440_rs::VersionSpecifiers>()
        .is_ok_and(|specifiers| specifiers.contains(&version))
}

pub(super) fn reconcile_via(instances: &mut Vec<Instance>) {
    use std::collections::{BTreeSet, HashMap};
    let mut declarations: HashMap<(String, String, String), Vec<usize>> = HashMap::new();
    let mut lock_names: HashMap<(String, String), BTreeSet<String>> = HashMap::new();
    for (index, instance) in instances.iter().enumerate() {
        let (Some(codebase), Some(path)) =
            (&instance.provenance.codebase, &instance.provenance.path)
        else {
            continue;
        };
        if instance.python_lock.is_some() {
            lock_names
                .entry((codebase.clone(), path.clone()))
                .or_default()
                .insert(instance.reference.clone());
        } else if instance.reference.starts_with("python-requirement:") {
            declarations
                .entry((codebase.clone(), path.clone(), instance.reference.clone()))
                .or_default()
                .push(index);
        }
    }
    let mut changes = Vec::new();
    let mut matched_declarations: HashMap<usize, usize> = HashMap::new();
    for (index, instance) in instances.iter().enumerate() {
        let (Some(lock), Some(codebase), Some(path), Some(version)) = (
            &instance.python_lock,
            &instance.provenance.codebase,
            &instance.provenance.path,
            &instance.resolved_version,
        ) else {
            continue;
        };
        if !lock.via_complete {
            continue;
        }
        let mut direct = None;
        let mut declaration_index = None;
        let mut parents_valid = true;
        let mut has_parent = false;
        for via in &lock.via {
            if let Some(source) = via.strip_prefix("-r ") {
                let key = (
                    codebase.clone(),
                    source.to_owned(),
                    instance.reference.clone(),
                );
                let candidates: Vec<usize> = declarations
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|candidate| {
                        let item = &instances[*candidate];
                        item.provenance.line.is_some()
                            && matches_declared_version(item.requested_version.as_deref(), version)
                    })
                    .collect();
                if let [candidate] = candidates.as_slice() {
                    let item = &instances[*candidate];
                    direct = Some(crate::model::SourceLine {
                        path: source.to_owned(),
                        line: item.provenance.line.unwrap_or_default(),
                        sha256: item.provenance.sha256.clone(),
                    });
                    declaration_index = Some(*candidate);
                } else {
                    parents_valid = false;
                }
            } else {
                has_parent = true;
                let reference = format!("python-requirement:{via}");
                if !lock_names
                    .get(&(codebase.clone(), path.clone()))
                    .is_some_and(|names| names.contains(&reference))
                {
                    parents_valid = false;
                }
            }
        }
        let value = if direct.is_some() {
            Some(true)
        } else if has_parent && parents_valid {
            Some(false)
        } else {
            None
        };
        if let Some(candidate) = declaration_index {
            *matched_declarations.entry(candidate).or_default() += 1;
        }
        changes.push((index, value, direct, declaration_index));
    }
    let mut remove = BTreeSet::new();
    for (index, direct, source, declaration) in changes {
        instances[index].provenance.direct = direct;
        if let Some(lock) = &mut instances[index].python_lock {
            lock.direct_source = source;
        }
        if let Some(declaration) = declaration
            && matched_declarations.get(&declaration) == Some(&1)
        {
            remove.insert(declaration);
        }
    }
    let mut index = 0usize;
    instances.retain(|_| {
        let keep = !remove.contains(&index);
        index += 1;
        keep
    });
}

pub(super) fn parse(
    bytes: &[u8],
    codebase: &str,
    path: &str,
    budget: usize,
) -> Result<(Vec<Instance>, String)> {
    let text = std::str::from_utf8(bytes)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let hash = crate::digest(bytes);
    let source_eligible = !crate::discovery::has_untrusted_sources(text);
    let annotations = via_annotations(text);
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
        if line.len() > 1024 * 1024
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
        let mut hashes = Vec::new();
        let mut invalid_hash = false;
        while let Some(word) = words.next() {
            let hash_value = if word == "--hash" {
                match words.next() {
                    Some(value) => Some(value),
                    None => {
                        invalid_option = true;
                        None
                    }
                }
            } else {
                word.strip_prefix("--hash=")
            };
            if let Some(value) = hash_value {
                if let Some(value) = value.strip_prefix("sha256:")
                    && value.len() == 64
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    hashes.push(value.to_ascii_lowercase());
                } else {
                    invalid_hash = true;
                }
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
        let reference = format!("python-requirement:{name}");
        let occurrence = occurrences
            .entry((reference.clone(), requested.clone()))
            .or_default();
        let id = crate::digest(
            format!("requirement:{codebase:?}:{path:?}:{reference:?}:{requested:?}:{occurrence}")
                .as_bytes(),
        );
        *occurrence += 1;
        hashes.sort_unstable();
        hashes.dedup();
        let via = annotations.get(&line_number).cloned().unwrap_or_default();
        let sanitized_via: Vec<String> = via.iter().filter_map(|value| safe_via(value)).collect();
        let python_lock =
            (!hashes.is_empty() && !invalid_hash && version.is_some()).then_some(PythonLock {
                sha256: hashes,
                source_eligible,
                via_complete: !via.is_empty() && via.len() == sanitized_via.len(),
                via: sanitized_via,
                direct_source: None,
            });
        instances.push(Instance {
            id,
            reference,
            requested_version: requested,
            resolved_version: version,
            origin: if python_lock
                .as_ref()
                .is_some_and(|lock| lock.source_eligible)
            {
                Origin::Locked
            } else {
                Origin::Declared
            },
            provenance: Provenance {
                path: Some(path.to_owned()),
                sha256: hash.clone(),
                observed_at: crate::now(),
                codebase: Some(codebase.to_owned()),
                codebase_context_sha256: None,
                direct: None,
                resolution: (!requirement.marker.is_true())
                    .then(|| "environment marker not evaluated".into()),
                artifact_integrity: None,
                line: Some(line_number),
            },
            purl: None,
            cpe_product: None,
            upstream: None,
            identity_evidence: Vec::new(),
            python_lock,
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
    let description = if !instances.is_empty()
        && instances.iter().all(|item| item.python_lock.is_some())
    {
        "hash-pinned Python lock parsed; registry identity, dependency relationships and installation require separate verification"
    } else {
        "requirements declarations are not installed inventory; directness, source and dependency closure are unverified"
    };
    let detail = format!(
        "{description}; {unresolved} unpinned, {conditional} conditional and {unsupported} unsupported entries{unsupported_locations}; {}; {}",
        "public package identities require source confirmation",
        if line_limit {
            "100000 line limit reached"
        } else if truncated {
            "instance budget exhausted"
        } else {
            "includes, constraints and private indexes require review"
        }
    );
    Ok((
        instances,
        if source_eligible {
            detail
        } else {
            format!("{detail}; source options or includes prevent public identity verification")
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{parse, reconcile_via};

    #[test]
    fn keeps_pins_ranges_markers_and_hashes_without_executing_input() {
        let text = b"# sample\nRequests[security]==2.31.0 \\\n    --hash=sha256:abc\nurllib3>=1.26,<3\nwinpkg==1.2; sys_platform == 'win32'\nprivate @ https://user:secret@example.invalid/pkg.whl\n";
        let (items, detail) = parse(text, "workspace", "requirements.txt", 10).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].reference, "python-requirement:requests");
        assert_eq!(items[0].purl, None);
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
            assert!(detail.contains("public package identities require source confirmation"));
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
        assert_eq!(items[0].reference, "python-requirement:requests");
        assert_eq!(items[0].provenance.line, Some(1));
    }

    #[test]
    fn many_hashes_do_not_hide_a_valid_locked_requirement() {
        let mut content = String::from("example==1.2.3 \\\n");
        for index in 0..300 {
            content.push_str(&format!("    --hash=sha256:{index:064x}"));
            content.push_str(if index == 299 { "\n" } else { " \\\n" });
        }
        assert!(content.len() > 16 * 1024);
        let (items, detail) =
            parse(content.as_bytes(), "codebase", "requirements.lock", 10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].resolved_version.as_deref(), Some("1.2.3"));
        assert!(detail.contains("0 unsupported"));
    }

    #[test]
    fn generated_via_links_are_checked_against_local_declarations() {
        let root = "example>=1,<2\n";
        let hash = "a".repeat(64);
        let lock = format!(
            "example==1.2 --hash=sha256:{hash}\n    # via -r docker/requirements.txt\nchild==2.0 --hash=sha256:{hash}\n    # via example\nunknown==3.0 --hash=sha256:{hash}\n"
        );
        let (mut inputs, _) =
            parse(root.as_bytes(), "/project", "docker/requirements.txt", 10).unwrap();
        let (locks, _) =
            parse(lock.as_bytes(), "/project", "docker/requirements.lock", 10).unwrap();
        inputs.extend(locks);
        reconcile_via(&mut inputs);
        assert_eq!(inputs.len(), 3);
        let direct = inputs
            .iter()
            .find(|item| item.reference == "python-requirement:example")
            .unwrap();
        assert_eq!(direct.provenance.direct, Some(true));
        let source = direct
            .python_lock
            .as_ref()
            .unwrap()
            .direct_source
            .as_ref()
            .unwrap();
        assert_eq!(
            (&*source.path, source.line, &source.sha256),
            (
                "docker/requirements.txt",
                1,
                &crate::digest(root.as_bytes())
            )
        );
        let child = inputs
            .iter()
            .find(|item| item.reference == "python-requirement:child")
            .unwrap();
        assert_eq!(child.provenance.direct, Some(false));
        assert_eq!(child.python_lock.as_ref().unwrap().via, ["example"]);
        let unknown = inputs
            .iter()
            .find(|item| item.reference == "python-requirement:unknown")
            .unwrap();
        assert_eq!(unknown.provenance.direct, None);
    }

    #[test]
    fn unverified_or_incompatible_via_does_not_claim_directness() {
        let hash = "b".repeat(64);
        let lock = format!(
            "example==1.2 --hash=sha256:{hash}\n    # via -r docker/requirements.txt\nchild==2.0 --hash=sha256:{hash}\n    # via absent-parent\n"
        );
        let (mut inputs, _) =
            parse(b"example>=2\n", "/project", "docker/requirements.txt", 10).unwrap();
        inputs.extend(
            parse(lock.as_bytes(), "/project", "docker/requirements.lock", 10)
                .unwrap()
                .0,
        );
        reconcile_via(&mut inputs);
        assert_eq!(inputs.len(), 3);
        assert!(inputs.iter().all(|item| item.provenance.direct.is_none()));
    }
}
