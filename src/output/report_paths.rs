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

/// Present known codebase paths without changing the stored evidence or operational paths.
pub(super) fn relative_paths<'a>(text: &str, paths: impl IntoIterator<Item = &'a str>) -> String {
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
            #[cfg(target_os = "macos")]
            for directory in ["var", "tmp", "etc"] {
                if let Some(tail) = root.strip_prefix(&format!("/private/{directory}/")) {
                    raw.push(format!("/{directory}/{tail}"));
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
            variants
        })
        .collect();
    for (root, _, _, windows) in &mut mappings {
        if *windows {
            *root = root.to_ascii_lowercase();
        }
    }
    mappings.sort_by_key(|(root, _, _, _)| std::cmp::Reverse(root.len()));

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
        let Some(position) = next_matches.iter().flatten().min().copied() else {
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
        let found = if boundary_before && !in_url {
            mappings.iter().find(|(root, _, only_file, windows)| {
                if *only_file && !file_url {
                    return false;
                }
                let haystack = if *windows {
                    &windows_search.as_ref().expect("Windows search exists")[offset..]
                } else {
                    &search[offset..]
                };
                haystack.strip_prefix(root.as_str()).is_some_and(|suffix| {
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
                })
            })
        } else {
            None
        };
        if let Some((root, label, _, _)) = found {
            let suffix = &rest[root.len()..];
            let child = suffix.starts_with(['/', '\\']);
            if file_url {
                output.truncate(output.len() - file_prefix.len());
            }
            output.push_str(if child && !multiple { "." } else { label });
            offset += root.len();
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
