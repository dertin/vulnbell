fn file_url_search_text(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut offset = 0;
    for token in text.split_inclusive(char::is_whitespace) {
        let raw = token.as_bytes();
        if let Some(start) = raw
            .windows(5)
            .position(|window| window.eq_ignore_ascii_case(b"file:"))
        {
            let before = &token[..start];
            let boundary = before
                .chars()
                .next_back()
                .is_none_or(|ch| matches!(ch, '`' | '(' | '[' | '<' | '\'' | '"'));
            if boundary && !before.contains("://") {
                let mut index = start + 5;
                while index + 2 < raw.len() {
                    if raw[index] == b'%'
                        && raw[index + 1].is_ascii_hexdigit()
                        && raw[index + 2].is_ascii_hexdigit()
                    {
                        bytes[offset + index + 1] = raw[index + 1].to_ascii_uppercase();
                        bytes[offset + index + 2] = raw[index + 2].to_ascii_uppercase();
                        index += 3;
                    } else {
                        index += 1;
                    }
                }
            }
        }
        offset += raw.len();
    }
    String::from_utf8(bytes).expect("ASCII case changes preserve UTF-8")
}

#[cfg(windows)]
fn windows_short_path(root: &str) -> Option<String> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let input: Vec<u16> = std::ffi::OsStr::new(root)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: input is NUL-terminated; a null output and zero capacity query the required size.
    let size = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
            input.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size == 0 || size > 32768 {
        return None;
    }
    let mut output = vec![0u16; size as usize];
    // SAFETY: input is NUL-terminated and output has `size` writable UTF-16 elements.
    let length = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(
            input.as_ptr(),
            output.as_mut_ptr(),
            size,
        )
    };
    if length == 0 || length >= size {
        return None;
    }
    Some(
        std::ffi::OsString::from_wide(&output[..length as usize])
            .to_string_lossy()
            .into_owned(),
    )
}

fn windows_mixed_patterns(root: &str, short: &str) -> Vec<(regex::Regex, bool)> {
    let normalize = |path: &str| {
        if let Some(tail) = path.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{tail}")
        } else {
            path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
        }
    };
    let root = normalize(root);
    let short = normalize(short);
    let unc = root.starts_with(r"\\");
    let long_parts: Vec<&str> = root.split('\\').collect();
    let short_parts: Vec<&str> = short.split('\\').collect();
    if long_parts.len() != short_parts.len() {
        return Vec::new();
    }
    [
        (r"\", false, false, false),
        (r"\\", false, false, true),
        ("/", false, false, false),
        ("/", true, true, false),
    ]
    .into_iter()
    .filter_map(|(separator, encoded, only_file, markdown)| {
        let parts: Vec<String> = long_parts
            .iter()
            .zip(&short_parts)
            .map(|(long, short)| {
                let encode = |part: &str| {
                    if encoded {
                        let mut url = url::Url::parse("file:///").expect("static URL");
                        url.set_path(&format!("/{part}"));
                        url.path().trim_start_matches('/').to_owned()
                    } else if markdown {
                        super::markdown::inline(part)
                    } else {
                        part.to_owned()
                    }
                };
                let long = regex::escape(&encode(long));
                let short = regex::escape(&encode(short));
                if long == short {
                    long
                } else {
                    format!("(?:{long}|{short})")
                }
            })
            .collect();
        let normal = parts.join(&regex::escape(separator));
        let pattern = if encoded {
            format!("(?i){normal}")
        } else {
            let prefix = match (unc, separator) {
                (true, r"\") => r"\\?\UNC\",
                (true, r"\\") => r"\\\\?\\UNC\\",
                (true, _) => "//?/UNC/",
                (false, r"\") => r"\\?\",
                (false, r"\\") => r"\\\\?\\",
                (false, _) => "//?/",
            };
            let tail = if unc { &parts[2..] } else { &parts[..] };
            format!(
                "(?i)(?:{normal}|{}{})",
                regex::escape(prefix),
                tail.join(&regex::escape(separator))
            )
        };
        regex::Regex::new(&pattern)
            .ok()
            .map(|pattern| (pattern, only_file))
    })
    .collect()
}

/// Present known codebase paths without changing the stored evidence or operational paths.
pub(super) fn relative_paths<'a>(text: &str, paths: impl IntoIterator<Item = &'a str>) -> String {
    relative_paths_with_aliases(text, paths, |root| {
        #[cfg(windows)]
        {
            windows_short_path(root)
        }
        #[cfg(not(windows))]
        {
            let _ = root;
            None
        }
    })
}

fn relative_paths_with_aliases<'a>(
    text: &str,
    paths: impl IntoIterator<Item = &'a str>,
    short_path: impl Fn(&str) -> Option<String>,
) -> String {
    let mut roots: Vec<&str> = paths
        .into_iter()
        .map(|path| path.trim_end_matches(['/', '\\']))
        .filter(|root| {
            root.starts_with('/')
                || root.starts_with("\\\\")
                || (root.len() > 3
                    && root.as_bytes()[0].is_ascii_alphabetic()
                    && root.as_bytes()[1] == b':'
                    && matches!(root.as_bytes()[2], b'/' | b'\\'))
        })
        .collect();
    roots.sort_unstable();
    roots.dedup();
    if roots.is_empty() {
        return text.to_owned();
    }
    let multiple = roots.len() > 1;
    let mut mixed_hits: Vec<(usize, usize, String, bool)> = Vec::new();
    let mut mappings: Vec<(String, String, bool, bool)> = roots
        .into_iter()
        .enumerate()
        .flat_map(|(index, root)| {
            let windows =
                root.starts_with("\\\\") || (root.len() > 2 && root.as_bytes()[1] == b':');
            let name = root.rsplit(['/', '\\']).next().unwrap_or(root);
            let label = if multiple {
                format!("{name}-{}", index + 1)
            } else {
                name.to_owned()
            };
            let label = super::markdown::inline(&label);
            let mut raw = vec![root.to_owned()];
            let short = windows.then(|| short_path(root)).flatten();
            if let Some(short) = &short {
                if let Some(tail) = short.strip_prefix(r"\\?\") {
                    raw.push(tail.to_owned());
                }
                raw.push(short.clone());
            }
            #[cfg(target_os = "macos")]
            for directory in ["var", "tmp", "etc"] {
                if let Some(tail) = root.strip_prefix(&format!("/private/{directory}"))
                    && (tail.is_empty() || tail.starts_with('/'))
                {
                    raw.push(format!("/{directory}{tail}"));
                }
            }
            if let Some(tail) = root.strip_prefix(r"\\?\UNC\") {
                raw.push(format!(r"\\{tail}"));
            } else if let Some(tail) = root.strip_prefix(r"\\?\") {
                raw.push(tail.to_owned());
            }
            let mut variants = Vec::new();
            for path in raw {
                variants.push((path.clone(), label.clone(), false, windows));
                let escaped = super::markdown::inline(&path);
                if escaped != path {
                    variants.push((escaped, label.clone(), false, windows));
                }
                if path.contains('\\') {
                    variants.push((path.replace('\\', "/"), label.clone(), false, windows));
                }
                let portable = path.replace('\\', "/");
                let mut file_url = url::Url::parse("file:///").expect("static file URL is valid");
                file_url.set_path(&portable);
                let encoded = if portable.starts_with('/') {
                    file_url.path()
                } else {
                    file_url.path().strip_prefix('/').unwrap_or(file_url.path())
                };
                if encoded != portable {
                    variants.push((encoded.to_owned(), label.clone(), true, windows));
                }
            }
            if let Some(short) = &short {
                for (pattern, only_file) in windows_mixed_patterns(root, short) {
                    for found in pattern.find_iter(text) {
                        mixed_hits.push((found.start(), found.len(), label.clone(), only_file));
                    }
                }
            }
            variants
        })
        .collect();
    for (root, _, _, windows) in &mut mappings {
        if *windows {
            *root = root.to_ascii_lowercase();
        }
    }
    mappings.sort_unstable();
    mappings.dedup();
    mappings.sort_by_key(|(root, _, _, _)| std::cmp::Reverse(root.len()));
    mixed_hits.sort_unstable_by(|a, b| {
        (a.0, std::cmp::Reverse(a.1), &a.2, a.3).cmp(&(b.0, std::cmp::Reverse(b.1), &b.2, b.3))
    });
    mixed_hits.dedup();
    let mut mixed_index = 0;

    let search = file_url_search_text(text);
    let windows_search = mappings
        .iter()
        .any(|(_, _, _, windows)| *windows)
        .then(|| search.to_ascii_lowercase());
    let mut next_matches: Vec<Option<usize>> = mappings
        .iter()
        .map(|(root, _, _, windows)| {
            let haystack = if *windows {
                windows_search.as_ref().expect("Windows search exists")
            } else {
                &search
            };
            haystack.find(root)
        })
        .collect();

    let mut output = String::with_capacity(text.len());
    let mut offset = 0;
    let mut token_start = 0;
    let mut token_end = 0;
    let mut token_has_url = false;
    while offset < text.len() {
        let rest = &text[offset..];
        while mixed_hits
            .get(mixed_index)
            .is_some_and(|hit| hit.0 < offset)
        {
            mixed_index += 1;
        }
        let position = next_matches
            .iter()
            .flatten()
            .min()
            .copied()
            .into_iter()
            .chain(mixed_hits.get(mixed_index).map(|hit| hit.0))
            .min();
        let Some(position) = position else {
            output.push_str(rest);
            break;
        };
        let distance = position - offset;
        output.push_str(&rest[..distance]);
        offset += distance;
        let rest = &text[offset..];
        let previous = text[..offset].chars().next_back();
        if offset >= token_end {
            if let Some((index, ch)) = text[token_end..offset]
                .char_indices()
                .rev()
                .find(|(_, ch)| ch.is_whitespace())
            {
                token_start = token_end + index + ch.len_utf8();
            }
            token_end = offset + rest.find(char::is_whitespace).unwrap_or(rest.len());
            token_has_url = text[token_start..token_end].contains("://");
        }
        let token_prefix = &text[token_start..offset];
        let file_prefix = [
            "file://localhost/",
            "file://localhost",
            "file:///",
            "file://",
            "file:",
        ]
        .into_iter()
        .find(|prefix| {
            if *prefix == "file:" && !rest.starts_with("//") {
                return false;
            }
            token_prefix
                .len()
                .checked_sub(prefix.len())
                .is_some_and(|start| {
                    let Some((before, candidate)) = token_prefix.split_at_checked(start) else {
                        return false;
                    };
                    candidate.eq_ignore_ascii_case(prefix)
                        && !before.contains("://")
                        && before
                            .chars()
                            .next_back()
                            .is_none_or(|ch| matches!(ch, '`' | '(' | '[' | '<' | '\'' | '"'))
                })
        })
        .unwrap_or("");
        let file_url = !file_prefix.is_empty();
        let boundary_before = file_url
            || previous.is_none_or(|ch| {
                !ch.is_alphanumeric() && !matches!(ch, '/' | '\\' | '_' | '-' | '.')
            });
        let in_url = token_has_url && !file_url;
        let suffix_valid = |suffix: &str| {
            suffix.chars().next().is_none_or(|ch| {
                (ch == '.'
                    && suffix[1..]
                        .chars()
                        .next()
                        .is_none_or(|next| !next.is_alphanumeric()))
                    || matches!(
                        ch,
                        '/' | '\\' | ':' | ')' | ']' | '}' | ',' | ';' | '`' | '\'' | '"'
                    )
                    || ch.is_whitespace()
            })
        };
        let found = if boundary_before && !in_url {
            let literal = mappings
                .iter()
                .find(|(root, _, only_file, windows)| {
                    if *only_file && !file_url {
                        return false;
                    }
                    let haystack = if *windows {
                        &windows_search.as_ref().expect("Windows search exists")[offset..]
                    } else {
                        &search[offset..]
                    };
                    haystack
                        .strip_prefix(root.as_str())
                        .is_some_and(suffix_valid)
                })
                .map(|(root, label, _, _)| (root.len(), label.as_str()));
            let mixed = mixed_hits[mixed_index..]
                .iter()
                .take_while(|hit| hit.0 == offset)
                .find(|(_, len, _, only_file)| {
                    (!only_file || file_url) && suffix_valid(&rest[*len..])
                })
                .map(|(_, len, label, _)| (*len, label.as_str()));
            match (literal, mixed) {
                (Some(literal), Some(mixed)) if mixed.0 > literal.0 => Some(mixed),
                (Some(literal), _) => Some(literal),
                (None, mixed) => mixed,
            }
        } else {
            None
        };
        if let Some((length, label)) = found {
            let suffix = &rest[length..];
            let child = suffix.starts_with(['/', '\\']);
            if file_url {
                output.truncate(output.len() - file_prefix.len());
            }
            output.push_str(if child && !multiple { "." } else { label });
            offset += length;
            if suffix.starts_with('\\') {
                let escaped = suffix.starts_with("\\\\");
                let delimiter = if file_url {
                    token_prefix.chars().next()
                } else {
                    previous
                };
                let length = suffix
                    .find(|ch: char| {
                        if let Some(quote @ ('`' | '\'' | '"')) = delimiter {
                            ch == quote || matches!(ch, '\n' | '\r')
                        } else {
                            ch.is_whitespace()
                                || matches!(
                                    ch,
                                    '`' | '"'
                                        | '\''
                                        | '<'
                                        | '>'
                                        | '('
                                        | ')'
                                        | '['
                                        | ']'
                                        | '{'
                                        | '}'
                                        | ','
                                        | ';'
                                )
                        }
                    })
                    .unwrap_or(suffix.len());
                let path = &suffix[..length];
                if escaped {
                    output.push_str(&path.replace("\\\\", "/"));
                } else {
                    output.push_str(&path.replace('\\', "/"));
                }
                offset += length;
            }
        } else {
            let ch = rest.chars().next().expect("offset is inside text");
            output.push(ch);
            offset += ch.len_utf8();
        }
        for ((root, _, _, windows), next) in mappings.iter().zip(&mut next_matches) {
            if next.is_some_and(|position| position < offset) {
                let haystack = if *windows {
                    windows_search.as_ref().expect("Windows search exists")
                } else {
                    &search
                };
                *next = haystack[offset..]
                    .find(root)
                    .map(|position| offset + position);
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::relative_paths;

    #[test]
    fn windows_alias_patterns_match_mixed_short_and_long_components() {
        let patterns = super::windows_mixed_patterns(
            r"\\?\C:\Users\Runner Administrator\AppData\Local\project",
            r"\\?\C:\Users\RUNNER~1\APPDAT~1\Local\project",
        );
        for path in [
            r"C:\Users\RUNNER~1\AppData\Local\project\src\app.rs",
            r"C:\Users\Runner Administrator\APPDAT~1\Local\project\src\app.rs",
            r"C:\\Users\\RUNNER~1\\AppData\\Local\\project\\src\\app.rs",
            "C:/Users/RUNNER~1/AppData/Local/project/src/app.rs",
        ] {
            assert!(
                patterns
                    .iter()
                    .any(|(pattern, only_file)| !only_file && pattern.is_match(path)),
                "{path}"
            );
        }
        assert!(patterns.iter().any(|(pattern, only_file)| {
            *only_file
                && pattern
                    .is_match("C:/Users/Runner%20Administrator/APPDAT~1/Local/project/src/app.rs")
        }));
    }

    #[test]
    fn windows_mixed_aliases_are_redacted_in_report_text() {
        let root = r"\\?\C:\Users\Runner Administrator\_private\project";
        let short = r"\\?\C:\Users\RUNNER~1\PRIVAT~1\project";
        let text = concat!(
            "C:\\Users\\RUNNER~1\\_private\\project\\src\\app.rs:1\n",
            "\\\\?\\C:\\Users\\RUNNER~1\\_private\\project\\src\\app.rs:1\n",
            "C:\\\\Users\\\\RUNNER~1\\\\\\_private\\\\project\\\\src\\\\app.rs:1\n",
            "file:///C:/Users/Runner%20Administrator/PRIVAT~1/project/src/app.rs:1\n",
            "https://example.org/C:/Users/RUNNER~1/_private/project/src/app.rs\n",
        );
        let report = super::relative_paths_with_aliases(text, [root], |_| Some(short.to_owned()));
        assert_eq!(report.matches("./src/app.rs:1").count(), 4, "{report}");
        assert!(
            report.contains("https://example.org/C:/Users/RUNNER~1/_private/project/src/app.rs")
        );
    }

    #[test]
    fn windows_unc_mixed_aliases_are_redacted_in_report_text() {
        let root = r"\\?\UNC\server\Runner Administrator\_private\project";
        let short = r"\\?\UNC\server\RUNNER~1\PRIVAT~1\project";
        let text = r"\\?\UNC\server\RUNNER~1\_private\project\src\app.rs:1";
        let report = super::relative_paths_with_aliases(text, [root], |_| Some(short.to_owned()));
        assert_eq!(report, "./src/app.rs:1");
    }

    #[test]
    fn many_distinct_windows_aliases_remain_portable() {
        let long: Vec<String> = (0..13)
            .map(|index| format!("LongComponent{index:02}"))
            .collect();
        let short: Vec<String> = (0..13).map(|index| format!("SHORT{index:02}~1")).collect();
        let root = format!("C:\\{}", long.join("\\"));
        let short_root = format!("C:\\{}", short.join("\\"));
        let mut text = String::new();
        for bits in 0..8192 {
            text.push_str("C:");
            for index in 0..13 {
                text.push('\\');
                text.push_str(if bits & (1 << index) == 0 {
                    &long[index]
                } else {
                    &short[index]
                });
            }
            text.push_str("\\src\\app.rs:1\n");
        }
        let report = super::relative_paths_with_aliases(&text, [root.as_str()], |_| {
            Some(short_root.clone())
        });
        assert_eq!(report.matches("./src/app.rs:1").count(), 8192);
    }

    #[cfg(windows)]
    #[test]
    fn repeated_windows_paths_are_normalized_without_duplicate_mappings() {
        let directory = tempfile::tempdir().unwrap();
        let canonical = directory.path().canonicalize().unwrap();
        let root = canonical.to_str().unwrap();
        let path = directory.path().to_str().unwrap();
        let text = format!("{path}/src/app.rs:1\n").repeat(10_000);
        let report = relative_paths(&text, [root]);
        assert_eq!(report.matches("./src/app.rs:1").count(), 10_000);
        assert!(!report.contains(path));
    }

    #[test]
    fn relative_paths_keep_line_numbers_and_external_urls() {
        let revisions = ["/home/alex/project"];
        let text = "/home/alex/project `/home/alex/project/docker/compose.yml:165` /home/alex/project-other /home/alex/project.txt https://example.org/home/alex/project/file https://example.org/?path=/home/alex/project/file";
        assert_eq!(
            relative_paths(text, revisions),
            "project `./docker/compose.yml:165` /home/alex/project-other /home/alex/project.txt https://example.org/home/alex/project/file https://example.org/?path=/home/alex/project/file"
        );
    }

    #[test]
    fn multiple_and_nested_codebases_are_unambiguous() {
        let revisions = ["/a/project", "/b/project", "/a/project/nested"];
        assert_eq!(
            relative_paths(
                "/a/project/src/a.rs:1 /b/project/src/b.rs:2 /a/project/nested/src/c.rs:3",
                revisions
            ),
            "project-1/src/a.rs:1 project-3/src/b.rs:2 nested-2/src/c.rs:3"
        );
    }

    #[test]
    fn windows_codebases_use_portable_relative_paths() {
        let roots = [r"C:\Users\alex\project"];
        assert_eq!(
            relative_paths(r"C:\Users\alex\project\src\main.rs:12", roots),
            "./src/main.rs:12"
        );
        assert_eq!(
            relative_paths(r"C:\\Users\\alex\\project\\src\\main.rs:12", roots),
            "./src/main.rs:12"
        );
        assert_eq!(
            relative_paths(r"c:\users\ALEx\PROJECT\src\main.rs:12", roots),
            "./src/main.rs:12"
        );
    }

    #[test]
    fn local_file_urls_are_relative_without_rewriting_https_urls() {
        let roots = ["/home/alex/project"];
        assert_eq!(
            relative_paths(
                "`file:///home/alex/project/src/main.rs:12` https://example.org/?path=file:///home/alex/project/a",
                roots
            ),
            "`./src/main.rs:12` https://example.org/?path=file:///home/alex/project/a"
        );
        assert_eq!(
            relative_paths("[source](file:///home/alex/project/src/main.rs:12)", roots),
            "[source](./src/main.rs:12)"
        );
    }

    #[test]
    fn windows_verbatim_unc_and_file_urls_are_portable() {
        let roots = [r"\\?\C:\Users\alex\project"];
        assert_eq!(
            relative_paths(r"\\?\C:\Users\alex\project\src\main.rs:12", roots),
            "./src/main.rs:12"
        );
        assert_eq!(
            relative_paths(
                r"Historical source: C:\Users\alex\project/src/old.rs:17",
                roots
            ),
            "Historical source: ./src/old.rs:17"
        );
        assert_eq!(
            relative_paths("file:///C:/Users/alex/project/src/main.rs:12", roots),
            "./src/main.rs:12"
        );
        assert_eq!(
            relative_paths(
                "file://LOCALHOST/C:/Users/alex/project/src/main.rs:12",
                roots
            ),
            "./src/main.rs:12"
        );
        let roots = [r"\\server\share\project"];
        assert_eq!(
            relative_paths(r#""\\server\share\project\My Folder\file.rs:12""#, roots),
            r#""./My Folder/file.rs:12""#
        );
        assert_eq!(
            relative_paths("file://server/share/project/src/main.rs:12", roots),
            "./src/main.rs:12"
        );
        let roots = [r"\\?\UNC\server\share\project"];
        assert_eq!(
            relative_paths(r"\\server\share\project\src\main.rs:12", roots),
            "./src/main.rs:12"
        );
    }

    #[test]
    fn percent_encoded_local_file_urls_use_relative_paths() {
        let roots = ["/home/alex/My Prójéct"];
        assert_eq!(
            relative_paths(
                "file://localhost/home/alex/My%20Pr%C3%B3j%C3%A9ct/src/main.rs:12",
                roots
            ),
            "./src/main.rs:12"
        );
        assert_eq!(
            relative_paths(
                "file:///home/alex/My%20Pr%c3%B3j%c3%a9ct/src/main.rs:12",
                roots
            ),
            "./src/main.rs:12"
        );
        assert_eq!(
            relative_paths(
                "https://example.org/home/alex/My%20Pr%C3%B3j%C3%A9ct/src/main.rs",
                roots
            ),
            "https://example.org/home/alex/My%20Pr%C3%B3j%C3%A9ct/src/main.rs"
        );
        let roots = [r"C:\Users\alex\My Project"];
        assert_eq!(
            relative_paths("file:///C:/Users/alex/My%20Project/src/main.rs:12", roots),
            "./src/main.rs:12"
        );
    }

    #[test]
    fn markdown_escaped_roots_are_normalized() {
        let roots = ["/home/alex/_project"];
        assert_eq!(
            relative_paths(r"`/home/alex/\_project/src/main.rs:4`", roots),
            "`./src/main.rs:4`"
        );
    }

    #[test]
    fn repeated_paths_in_one_token_remain_bounded_and_relative() {
        let root = "/home/alex/project";
        let text = format!("({root}/file.rs),").repeat(10_000);
        let output = relative_paths(&text, [root]);
        assert_eq!(output.matches("./file.rs").count(), 10_000);
        let windows_root = r"C:\Users\alex\_project";
        let text = format!(r"({windows_root}\src\file.rs),").repeat(10_000);
        let output = relative_paths(&text, [windows_root]);
        assert_eq!(output.matches("./src/file.rs").count(), 10_000);
    }
}
